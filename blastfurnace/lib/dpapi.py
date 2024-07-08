from __future__ import annotations

import base64
import dataclasses
import typing as t
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

# static const BYTE gmsaSecurityDescriptor[] = {/* O:SYD:(A;;FRFW;;;S-1-5-9) */
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68
GmsaSecurityDescriptor = bytes([0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9,
                0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0])

_EPOCH_FILETIME = 116444736000000000  # 1970-01-01 as FILETIME
KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")
GMSA_LABEL = "GMSA PASSWORD\0".encode("utf-16-le")

@dataclasses.dataclass(frozen=True)
class KeyIdentifier:
    """Key Identifier.

    This contains the key identifier info that can be used by MS-GKDI GetKey
    to retrieve the group key seed values. This structure is not defined
    publicly by Microsoft but it closely matches the :class:`GroupKeyEnvelope`
    structure.

    Args:
        version: The version of the structure, should be 1
        flags: Flags describing the values inside the structure
        l0: The L0 index of the key
        l1: The L1 index of the key
        l2: The L2 index of the key
        root_key_identifier: The key identifier
        key_info: If is_public_key this is the public key, else it is the key
            KDF context value.
        domain_name: The domain name of the server in DNS format.
        forest_name: The forest name of the server in DNS format.
    """

    version: int
    magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    key_info: bytes
    domain_name: str
    forest_name: str

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    def pack(self) -> bytes:
        b_domain_name = (self.domain_name + "\00").encode("utf-16-le")
        b_forest_name = (self.forest_name + "\00").encode("utf-16-le")

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little"),
                self.magic,
                self.flags.to_bytes(4, byteorder="little"),
                self.l0.to_bytes(4, byteorder="little"),
                self.l1.to_bytes(4, byteorder="little"),
                self.l2.to_bytes(4, byteorder="little"),
                self.root_key_identifier.bytes_le,
                len(self.key_info).to_bytes(4, byteorder="little"),
                len(b_domain_name).to_bytes(4, byteorder="little"),
                len(b_forest_name).to_bytes(4, byteorder="little"),
                self.key_info,
                b_domain_name,
                b_forest_name,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KeyIdentifier:
        view = memoryview(data)

        version = int.from_bytes(view[:4], byteorder="little")

        if view[4:8].tobytes() != cls.magic:
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

        flags = int.from_bytes(view[8:12], byteorder="little")
        l0_index = int.from_bytes(view[12:16], byteorder="little")
        l1_index = int.from_bytes(view[16:20], byteorder="little")
        l2_index = int.from_bytes(view[20:24], byteorder="little")
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        key_info_len = int.from_bytes(view[40:44], byteorder="little")
        domain_len = int.from_bytes(view[44:48], byteorder="little")
        forest_len = int.from_bytes(view[48:52], byteorder="little")
        view = view[52:]

        key_info = view[:key_info_len].tobytes()
        view = view[key_info_len:]

        # Take away 2 for the final null padding
        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        return KeyIdentifier(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            key_info=key_info,
            domain_name=domain,
            forest_name=forest,
        )

# effectively the same as the GetKey() call that returns
# the GKE for a given rootKey
def get_gke_from_cache(
    root_key_identifier: uuid.UUID,
    target_sd: bytes,
    cache: KeyCache,
) -> t.Optional[GroupKeyEnvelope]:
    if not root_key_identifier:
        return None

    # MS-GKDI 3.1.4.1 GetKey rules on how to generate the group key identifier
    # values from the current time
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39
    current_time = (time.time_ns() // 100) + _EPOCH_FILETIME
    base = 360000000000  # 3.6 * 10**11
    l0 = int(current_time / (32 * 32 * base))
    l1 = int((current_time % (32 * 32 * base)) / (32 * base))
    l2 = int((current_time % (32 * base)) / base)

    rk = cache._get_key(
        target_sd,
        root_key_identifier,
        l0,
        l1,
        l2,
    )
    if not rk:
        return None

    kdf_parameters = KDFParameters.unpack(rk.kdf_parameters)
    l1_key, l2_key = compute_l2_key(
        kdf_parameters.hash_algorithm,
        l1,
        l2,
        rk,
    )

    if l1 == 0:
        l1_key = b""

    return GroupKeyEnvelope(
        version=rk.version,
        flags=rk.flags,
        l0=l0,
        l1=l1,
        l2=l2,
        root_key_identifier=root_key_identifier,
        kdf_algorithm=rk.kdf_algorithm,
        kdf_parameters=rk.kdf_parameters,
        secret_algorithm=rk.secret_algorithm,
        secret_parameters=rk.secret_parameters,
        private_key_length=rk.private_key_length,
        public_key_length=rk.public_key_length,
        domain_name=rk.domain_name,
        forest_name=rk.forest_name,
        l1_key=l1_key,
        l2_key=l2_key,
    )


class RootKey(t.NamedTuple):
    """The KDS Root Key."""

    key: bytes
    version: int
    kdf_algorithm: str
    kdf_parameters: bytes
    secret_algorithm: str
    secret_parameters: t.Optional[bytes]
    private_key_length: int
    public_key_length: int


class KeyCache:
    """Key Cache.

    This is a cache used to store the KDS keys.
    """

    def __init__(self) -> None:
        self._root_keys: t.Dict[uuid.UUID, RootKey] = {}
        self._seed_keys: t.Dict[uuid.UUID, t.Dict[bytes, t.Dict[int, GroupKeyEnvelope]]] = {}

    def load_key(
        self,
        key: bytes,
        root_key_id: uuid.UUID,
        version: int = 1,
        kdf_algorithm: str = "SP800_108_CTR_HMAC",
        kdf_parameters: bytes = None,
        secret_algorithm: str = "DH",
        secret_parameters: t.Optional[bytes] = None,
        private_key_length: int = 512,
        public_key_length: int = 2048,
    ) -> None:
        """Load a KDS root key into the cache.

        This loads the KDS root key provided into the cache for use in future
        operations.

        A domain administrator can retrieve the required information from a DC
        using this PowerShell code.

        .. code-block:: powershell

            $configurationContext = (Get-ADRootDSE).configurationNamingContext
            $getParams = @{
                LDAPFilter = '(objectClass=msKds-ProvRootKey)'
                SearchBase = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configurationContext"
                SearchScope = 'OneLevel'
                Properties = @(
                    'cn'
                    'msKds-KDFAlgorithmID'
                    'msKds-KDFParam'
                    'msKds-SecretAgreementAlgorithmID'
                    'msKds-SecretAgreementParam'
                    'msKds-PrivateKeyLength'
                    'msKds-PublicKeyLength'
                    'msKds-RootKeyData'
                )
            }
            Get-ADObject @getParams | ForEach-Object {
                [PSCustomObject]@{
                    Version = 1
                    RootKeyId = [Guid]::new($_.cn)
                    KdfAlgorithm = $_.'msKds-KDFAlgorithmID'
                    KdfParameters = [System.Convert]::ToBase64String($_.'msKds-KDFParam')
                    SecretAgreementAlgorithm = $_.'msKds-SecretAgreementAlgorithmID'
                    SecretAgreementParameters = [System.Convert]::ToBase64String($_.'msKds-SecretAgreementParam')
                    PrivateKeyLength = $_.'msKds-PrivateKeyLength'
                    PublicKeyLength = $_.'msKds-PublicKeyLength'
                    RootKeyData = [System.Convert]::ToBase64String($_.'msKds-RootKeyData')
                }
            }

        It can also be retrieved using this OpenLDAP command:

        .. code-block:: bash

            ldapsearch \
                -b 'CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=domain,DC=test' \
                -s one \
                '(objectClass=msKds-ProvRootKey)' \
                cn \
                msKds-KDFAlgorithmID \
                msKds-KDFParam \
                msKds-SecretAgreementAlgorithmID \
                msKds-SecretAgreementParam \
                msKds-PrivateKeyLength \
                msKds-PublicKeyLength \
                msKds-RootKeyData

        Args:
            key: The root key bytes stored in ``msKds-RootKeyData``.
            root_key_id: The root key id as stored in ``cn``.
            version: The key version number.
            kdf_algorithm: The KDF algorithm name stored in
                ``msKds-KDFAlgorithmID``.
            kdf_parameters: The KDF parameters stored in ``msKds-KDFParam`.
            secret_algorithm: The secret agreement algorithm stored in
                ``msKds-SecretAgreementAlgorithmID``.
            secret_parameters: The secret agreement parameters stored in
                ``msKds-SecretAgreementParam``.
            private_key_length: The private key length stored in
                ``msKds-PrivateKeyLength``.
            public_key_length: The public key length stored in
                ``msKds-PublicKeyLength``.
        """

        self._root_keys[root_key_id] = RootKey(
            key=key,
            version=version,
            kdf_algorithm=kdf_algorithm,
            kdf_parameters=kdf_parameters,
            secret_algorithm=secret_algorithm,
            secret_parameters=secret_parameters,
            private_key_length=private_key_length,
            public_key_length=public_key_length,
        )

    def dump_keys(self):

        for rkid in self._root_keys.keys():
            rk = self._root_keys.get(rkid, None)
            print(rk)

    def _get_key(
        self,
        target_sd: bytes,
        root_key_id: uuid.UUID,
        l0: int,
        l1: int,
        l2: int,
    ) -> t.Optional[GroupKeyEnvelope]:
        """Get key from the cache.

        Attempts to get the key from a cache if it's available. A key is cached
        either from the root key stored in :meth:`load_key` or from a previous
        RPC call for the same target sd and root key id.

        Args:
            target_sd: The target security descriptor the key is for.
            root_key_id: The root key id requested.
            l0: The L0 index needed.
            l1: The L1 index needed.
            l2: The L2 index needed.

        Returns:
            Optional[GroupKeyEnvelope]: The cached key if one was available.
        """
        #seed_key = self._seed_keys.setdefault(root_key_id, {}).setdefault(target_sd, {}).get(l0, None)
        #if seed_key and (seed_key.l1 > l1 or (seed_key.l1 == l1 and seed_key.l2 >= l2)):
        #    return seed_key

        root_key = self._root_keys.get(root_key_id, None)
        if root_key:
            l1_seed = compute_l1_key(
                target_sd,
                root_key_id,
                l0,
                root_key.key,
                KDFParameters.unpack(root_key.kdf_parameters).hash_algorithm,
            )

            gke = GroupKeyEnvelope(
                version=root_key.version,
                flags=2,
                l0=l0,
                l1=31,
                l2=31,
                root_key_identifier=root_key_id,
                kdf_algorithm=root_key.kdf_algorithm,
                kdf_parameters=root_key.kdf_parameters,
                secret_algorithm=root_key.secret_algorithm,
                secret_parameters=root_key.secret_parameters or b"",
                private_key_length=root_key.private_key_length,
                public_key_length=root_key.public_key_length,
                domain_name="",
                forest_name="",
                l1_key=l1_seed,
                l2_key=b"",
            )
            return self._seed_keys.setdefault(root_key_id, {}).setdefault(target_sd, {}).setdefault(l0, gke)

        return None

@dataclasses.dataclass(frozen=True)
class KDFParameters:
    """KDF Parameters

    The format and field descriptions for the key derivation function (KDF)
    parameters. The format of this struct is defined in
    `MS-GKDI 2.2.1 KDF Parameters`_.

    Args:
        hash_name: The name of the hash algorithm.

    .. _MS-GKDI 2.2.1 KDF Parameters:
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187
    """

    hash_name: str

    @property
    def hash_algorithm(self) -> hashes.HashAlgorithm:
        """The hash algorithm object."""
        if self.hash_name == "SHA1":
            return hashes.SHA1()
        elif self.hash_name == "SHA256":
            return hashes.SHA256()
        elif self.hash_name == "SHA384":
            return hashes.SHA384()
        elif self.hash_name == "SHA512":
            return hashes.SHA512()
        else:
            raise NotImplementedError(f"Unsupported hash algorithm {self.hash_name}")

    def pack(self) -> bytes:
        b_hash_name = (self.hash_name + "\00").encode("utf-16-le")
        return b"".join(
            [
                b"\x00\x00\x00\x00\x01\x00\x00\x00",
                len(b_hash_name).to_bytes(4, byteorder="little"),
                b"\x00\x00\x00\x00",
                b_hash_name,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KDFParameters:
        view = memoryview(data)

        if view[:8].tobytes() != b"\x00\x00\x00\x00\x01\x00\x00\x00" or view[12:16].tobytes() != b"\x00\x00\x00\x00":
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

        hash_length = int.from_bytes(view[8:12], byteorder="little")
        hash_name = view[16 : 16 + hash_length - 2].tobytes().decode("utf-16-le")

        return KDFParameters(hash_name=hash_name)

@dataclasses.dataclass(frozen=True)
class GroupKeyEnvelope:
    """Group Key Envelope

    The group key envelope structure that describes the group key information
    returned by a GetKey RPC request. The format of this struct is defined in
    `MS-GKDI 2.2.4 Group Key Envelope`_.

    Args:
        version: The version of the structure, should be 1
        flags: Flags describing the values inside the structure
        l0: The L0 index of the key
        l1: The L1 index of the key
        l2: The L2 index of the key
        root_key_identifier: The key identifier
        kdf_algorithm: The KDF algorithm name.
        kdf_parameters: The KDF algorithm parameters
        secret_algorithm: The secret agreement algorithm name.
        secret_parameters: The secret agreement algorithm parameters.
        private_key_length: The private key length associated with the root key.
        public_key_length: The public key length associated with the root key.
        domain_name: The domain name of the server in DNS format.
        forest_name: The forest name of the server in DNS format.
        l1_key: The L1 seed key.
        l2_key: If is_public_key this is the public key, else this is the L2
            seed key.

    .. _MS-GKDI 2.2.4 Group Key Envelope
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
    """

    version: int
    magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    kdf_algorithm: str
    kdf_parameters: bytes
    secret_algorithm: str
    secret_parameters: bytes
    private_key_length: int
    public_key_length: int
    domain_name: str
    forest_name: str
    l1_key: bytes
    l2_key: bytes

    @property
    def is_public_key(self) -> bool:
        """If True, the value of l2_key is the public key."""
        return bool(self.flags & 1)

    def pack(self) -> bytes:
        b_kdf_algorithm = (self.kdf_algorithm + "\00").encode("utf-16-le")
        b_secret_algorithm = (self.secret_algorithm + "\00").encode("utf-16-le")
        b_domain_name = (self.domain_name + "\00").encode("utf-16-le")
        b_forest_name = (self.forest_name + "\00").encode("utf-16-le")

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little"),
                self.magic,
                self.flags.to_bytes(4, byteorder="little"),
                self.l0.to_bytes(4, byteorder="little"),
                self.l1.to_bytes(4, byteorder="little"),
                self.l2.to_bytes(4, byteorder="little"),
                self.root_key_identifier.bytes_le,
                len(b_kdf_algorithm).to_bytes(4, byteorder="little"),
                len(self.kdf_parameters).to_bytes(4, byteorder="little"),
                len(b_secret_algorithm).to_bytes(4, byteorder="little"),
                len(self.secret_parameters).to_bytes(4, byteorder="little"),
                self.private_key_length.to_bytes(4, byteorder="little"),
                self.public_key_length.to_bytes(4, byteorder="little"),
                len(self.l1_key).to_bytes(4, byteorder="little"),
                len(self.l2_key).to_bytes(4, byteorder="little"),
                len(b_domain_name).to_bytes(4, byteorder="little"),
                len(b_forest_name).to_bytes(4, byteorder="little"),
                b_kdf_algorithm,
                self.kdf_parameters,
                b_secret_algorithm,
                self.secret_parameters,
                b_domain_name,
                b_forest_name,
                self.l1_key,
                self.l2_key,
            ]
        )

    def get_gmsa_key(
        self,
        key_id: KeyIdentifier,
        sid: bytes,
    ) -> bytes:
        if self.is_public_key:
            raise ValueError("Current user is not authorized to retrieve the KEK information")
        if self.l0 != key_id.l0:
            raise ValueError(f"L0 index {self.l0} does not match the requested L0 index {key_id.l0}")
        if self.kdf_algorithm != "SP800_108_CTR_HMAC":
            raise NotImplementedError(f"Unknown KDF algorithm '{self.kdf_algorithm}'")
        if sid == b"":
            raise ValueError("SID value must be provided in bytes format")

        kdf_parameters = KDFParameters.unpack(self.kdf_parameters)
        hash_algo = kdf_parameters.hash_algorithm
        # the generated L1 key is not needed here
        _,l2_key = compute_l2_key(hash_algo, key_id.l1, key_id.l2, self)

        # this should never be set
        if key_id.is_public_key:
            return None
        else:
            return kdf(
                hash_algo,
                l2_key,
                GMSA_LABEL,
                sid,
                256,
            )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GroupKeyEnvelope:
        view = memoryview(data)

        version = int.from_bytes(view[:4], byteorder="little")

        if view[4:8].tobytes() != cls.magic:
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

        flags = int.from_bytes(view[8:12], byteorder="little")
        l0_index = int.from_bytes(view[12:16], byteorder="little")
        l1_index = int.from_bytes(view[16:20], byteorder="little")
        l2_index = int.from_bytes(view[20:24], byteorder="little")
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        kdf_algo_len = int.from_bytes(view[40:44], byteorder="little")
        kdf_para_len = int.from_bytes(view[44:48], byteorder="little")
        sec_algo_len = int.from_bytes(view[48:52], byteorder="little")
        sec_para_len = int.from_bytes(view[52:56], byteorder="little")
        priv_key_len = int.from_bytes(view[56:60], byteorder="little")
        publ_key_len = int.from_bytes(view[60:64], byteorder="little")
        l1_key_len = int.from_bytes(view[64:68], byteorder="little")
        l2_key_len = int.from_bytes(view[68:72], byteorder="little")
        domain_len = int.from_bytes(view[72:76], byteorder="little")
        forest_len = int.from_bytes(view[76:80], byteorder="little")
        view = view[80:]

        kdf_algo = view[: kdf_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[kdf_algo_len:]

        kdf_param = view[:kdf_para_len].tobytes()
        view = view[kdf_para_len:]

        secret_algo = view[: sec_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[sec_algo_len:]

        secret_param = view[:sec_para_len].tobytes()
        view = view[sec_para_len:]

        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        l1_key = view[:l1_key_len].tobytes()
        view = view[l1_key_len:]

        l2_key = view[:l2_key_len].tobytes()
        view = view[l2_key_len:]

        return GroupKeyEnvelope(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            kdf_algorithm=kdf_algo,
            kdf_parameters=kdf_param,
            secret_algorithm=secret_algo,
            secret_parameters=secret_param,
            private_key_length=priv_key_len,
            public_key_length=publ_key_len,
            domain_name=domain,
            forest_name=forest,
            l1_key=l1_key,
            l2_key=l2_key,
        )

def compute_l1_key(
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    root_key: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    # Note: 512 is number of bits, we use byte length here
    # Key(SD, RK, L0, -1, -1) = KDF(
    #   HashAlg,
    #   RK.msKds-RootKeyData,
    #   "KDS service",
    #   RKID || L0 || 0xffffffff || 0xffffffff,
    #   512
    # )


    l0_seed = kdf(
        algorithm,
        root_key,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key_id, l0, -1, -1),
        64,
    )

    # Key(SD, RK, L0, 31, -1) = KDF(
    #   HashAlg,
    #   Key(SD, RK, L0, -1, -1),
    #   "KDS service",
    #   RKID || L0 || 31 || 0xffffffff || SD,
    #   512
    # )
    return kdf(
        algorithm,
        l0_seed,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key_id, l0, 31, -1) + target_sd,
        64,
    )

def compute_l2_key(
    algorithm: hashes.HashAlgorithm,
    request_l1: int,
    request_l2: int,
    rk: GroupKeyEnvelope,
) -> tuple[bytes,bytes]:
    l1 = rk.l1
    l1_key = rk.l1_key
    l2 = rk.l2
    l2_key = rk.l2_key
    reseed_l2 = l2 == 31 or rk.l1 != request_l1

    # MS-GKDI 2.2.4 Group key Envelope
    # If the value in the L2 index field is equal to 31, this contains the
    # L1 key with group key identifier (L0 index, L1 index, -1). In all
    # other cases, this field contains the L1 key with group key identifier
    # (L0 index, L1 index - 1, -1). If this field is present, its length
    # MUST be equal to 64 bytes.
    if l2 != 31 and l1 != request_l1:
        l1 -= 1

    while l1 != request_l1:
        reseed_l2 = True
        l1 -= 1

        l1_key = kdf(
            algorithm,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                -1,
            ),
            64,
        )

    # addition from original library
    # an L1 key needs to be generated
    # when the request L1 Index is > 0
    if request_l1 > 0:
        adjusted_l1 = request_l1 - 1

        rk_l1_key = kdf(
                algorithm,
                l1_key,
                KDS_SERVICE_LABEL,
                compute_kdf_context(
                    rk.root_key_identifier,
                    rk.l0,
                    adjusted_l1,
                    -1,
                ),
                64
        )

    if reseed_l2:
        l2 = 31
        l2_key = kdf(
            algorithm,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    while l2 != request_l2:
        l2 -= 1

        l2_key = kdf(
            algorithm,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    return rk_l1_key, l2_key

def compute_kdf_context(
    key_guid: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
) -> bytes:
    return b"".join(
        [
            key_guid.bytes_le,
            l0.to_bytes(4, byteorder="little", signed=True),
            l1.to_bytes(4, byteorder="little", signed=True),
            l2.to_bytes(4, byteorder="little", signed=True),
        ]
    )

# Key Derivation Function used to in place of the windows API
# BcryptGenerateSymmetricKey and BcryptGenerateDerivationKey
# in SP800-108 counter mode.
def kdf(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    # KDF(HashAlg, KI, Label, Context, L)
    # where KDF is SP800-108 in counter mode.
    kdf = KBKDFHMAC(
        algorithm=algorithm,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        # MS-SMB2 uses the same KDF function and my implementation that
        # sets a value of 4 seems to work so assume that's the case here.
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf.derive(secret)
