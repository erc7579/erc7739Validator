// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_FALLBACK, CALLTYPE_SINGLE} from "modulekit/external/ERC7579.sol";
import { SampleK1ValidatorWithERC7739 } from "src/SampleK1ValidatorWithERC7739.sol";
import { EIP5267CompatibilityFallback } from "src/EIP5267CompatibilityFallback.sol";
import { ModuleInstallLib } from "src/utils/ModuleInstallLib.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

contract SampleERC7739ValidatorTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using ModuleInstallLib for bytes;

    bytes32 internal constant APP_DOMAIN_SEPARATOR = 0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    // account and modules
    AccountInstance internal instance;
    SampleK1ValidatorWithERC7739 internal validator;
    EIP5267CompatibilityFallback internal fallbackModule;
    Account owner;

    function setUp() public {
        init();

        // Create the validator
        validator = new SampleK1ValidatorWithERC7739();
        vm.label(address(validator), "SampleK1ValidatorWithERC7739");
        owner = makeAccount("owner");
        fallbackModule = new EIP5267CompatibilityFallback();

        // Create the account and install the validator
        instance = makeAccountInstance("Smart Account");
        vm.deal(address(instance.account), 10 ether);
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: abi.encodePacked(owner.addr).encodeAsValidatorData()
        });

        //install compatibility fallback
        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_SINGLE, "");
        instance.installModule({ moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback });
    }

    /// @notice Tests the validation of a personal signature
    function test_isValidSignature_ERC7739_PersonalSign_Success() public {
        TestTemps memory t;
        t.contents = keccak256("123");
        bytes32 hashToSign = toERC1271HashPersonalSign(t.contents, instance.account);
        (t.v, t.r, t.s) = vm.sign(owner.key, hashToSign);
        bytes memory signature = abi.encodePacked(t.r, t.s, t.v);
        
        vm.prank(instance.account);
        bytes4 res = validator.isValidSignatureWithSender(address(this), t.contents, signature);
        assertEq(res, bytes4(0x1626ba7e));
    }

    /// @notice Tests the validation of an EIP-712 typed data signature with a nested struct
    function test_isValidSignature_ERC7739_TypedData_Success_Explicit_Mode() public {
        TestTemps memory t;
        t.contents = keccak256("0x1234");
        bytes memory contentsType = "A(bytes32 stuff)Contents(A a)"; //encoded as per EIP-712
        bytes memory contentsName = "Contents";
        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName); //descr is contents type || contents name
        
        bytes32 dataToSign = toERC1271Hash(t.contents, instance.account, contentsType);
        (t.v, t.r, t.s) = vm.sign(owner.key, dataToSign);
        
        bytes memory signature = abi.encodePacked(t.r, t.s, t.v, APP_DOMAIN_SEPARATOR, t.contents, contentsDescription, uint16(contentsDescription.length)); 
        
        vm.prank(instance.account);
        bytes4 res = validator.isValidSignatureWithSender(address(this), toContentsHash(t.contents), signature);
        assertEq(res, bytes4(0x1626ba7e));
    }

    /// @notice Tests the validation of an EIP-712 typed data signature
    function test_isValidSignature_ERC7739_TypedData_Success_Implicit_Mode() public {
        TestTemps memory t;
        t.contents = keccak256("0x1234");
        bytes memory contentsType = "Contents(bytes32 stuff)"; 
        bytes memory contentsDescription = contentsType; //descr is just contents type

        bytes32 dataToSign = toERC1271Hash(t.contents, instance.account, contentsType);
        (t.v, t.r, t.s) = vm.sign(owner.key, dataToSign);
        
        bytes memory signature = abi.encodePacked(t.r, t.s, t.v, APP_DOMAIN_SEPARATOR, t.contents, contentsDescription, uint16(contentsDescription.length));
        
        vm.prank(instance.account);
        bytes4 res = validator.isValidSignatureWithSender(address(this), toContentsHash(t.contents), signature);
        assertEq(res, bytes4(0x1626ba7e));
    }

    /// @notice Tests the validation of an EIP-712 signature via safe sender.
    function test_isValidSignature_Vanilla1271_TypedData_SafeSender_Success() public {
        // add safe sender
        vm.prank(instance.account);
        validator.addSafeSender(address(this));

        TestTemps memory t;
        bytes32 dataToSign = hashTypedDataSecure(Mail({from: address(1), to: address(2), contents: "Moo!"}), instance.account);
        (t.v, t.r, t.s) = vm.sign(owner.key, dataToSign);
        bytes memory signature = abi.encodePacked(address(validator), t.r, t.s, t.v);

        bytes4 res = IERC7579Account(instance.account).isValidSignature(dataToSign, signature);
        assertEq(res, bytes4(0x1626ba7e));
    }


    /// @notice The validation of a vanilla EIP-712/ERC-1271 signature doesn't pass if the sender is not safe
    function test_isValidSignature_Vanilla1271_TypedData_Fails() public {
        // do not add safe sender
        TestTemps memory t;
        bytes32 dataToSign = hashTypedDataSecure(Mail({from: address(1), to: address(2), contents: "Moo!"}), instance.account);
        (t.v, t.r, t.s) = vm.sign(owner.key, dataToSign);
        bytes memory signature = abi.encodePacked(address(validator), t.r, t.s, t.v);

        // for basic account it reverts, as it doesn't wrap validator.isValidSignatureWithSender with try/catch
        // for Nexus, it would return 0xffffffff as Nexus does try/catch
        vm.expectRevert();
        bytes4 res = IERC7579Account(instance.account).isValidSignature(dataToSign, signature);
    }

    // ===== HELPERS ======

    struct TestTemps {
        bytes32 userOpHash;
        bytes32 contents;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 missingAccountFunds;
    }

    struct AccountDomainStruct {
        bytes1 fields;
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
        uint256[] extensions;
    }

    struct Mail {
        address from;
        address to;
        string contents;
    }

    /// @notice Generates an ERC-1271 hash for personal sign.
    /// @param childHash The child hash.
    /// @return The ERC-1271 hash for personal sign.
    function toERC1271HashPersonalSign(bytes32 childHash, address account) internal view returns (bytes32) {
        AccountDomainStruct memory t;
        (t.fields, t.name, t.version, t.chainId, t.verifyingContract, t.salt, t.extensions) = EIP712(account).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(t.name)),
                keccak256(bytes(t.version)),
                t.chainId,
                t.verifyingContract
            )
        );
        bytes32 parentStructHash = keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), childHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, parentStructHash));
    }

    /// @notice Generates an ERC-1271 hash for the given contents and account.
    /// @param contents The contents hash.
    /// @param account The account address.
    /// @return The ERC-1271 hash.
    function toERC1271Hash(bytes32 contents, address account, bytes memory contentsType) internal view returns (bytes32) {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(
                    keccak256(
                        abi.encodePacked(
                            "TypedDataSign(Contents contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                            contentsType
                        )
                    ),
                    contents
                ),
                accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", APP_DOMAIN_SEPARATOR, parentStructHash));
    }

    // @notice EIP-712 hash
    function hashTypedDataSecure(Mail memory mail, address account) internal view returns (bytes32) {
        bytes32 secureHash = keccak256(
            abi.encode(
                keccak256(
                        "Mail(address from,address to,string contents,address verifyingContract)"
                    ),
                mail.from,
                mail.to,
                keccak256(bytes(mail.contents)),
                account
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", APP_DOMAIN_SEPARATOR, secureHash));
    }

    /// @notice Generates a contents hash.
    /// @param contents The contents hash.
    /// @return The EIP-712 hash.
    function toContentsHash(bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", APP_DOMAIN_SEPARATOR, contents));
    }

    /// @notice Retrieves the EIP-712 domain struct fields.
    /// @param account The account address.
    /// @return The encoded EIP-712 domain struct fields.
    function accountDomainStructFields(address account) internal view returns (bytes memory) {
        AccountDomainStruct memory t;
        (t.fields, t.name, t.version, t.chainId, t.verifyingContract, t.salt, t.extensions) = EIP712(account).eip712Domain();

        return
            abi.encode(
                keccak256(bytes(t.name)),
                keccak256(bytes(t.version)),
                t.chainId,
                t.verifyingContract, // Use the account address as the verifying contract.
                t.salt
            );
    }
}
