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

contract SampleERC7739ValidatorTest_RPC is RhinestoneModuleKit, Test {
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
        
        //uint256 forkId = vm.createFork("https://ethereum-rpc.publicnode.com");
        //uint256 forkId = vm.createFork("https://ethereum-sepolia-rpc.publicnode.com");
        uint256 forkId = vm.createFork("http://localhost:8545"); // you need to run anvil first
        vm.selectFork(forkId);

        // etch basefee contract
        // See: https://gist.github.com/Vectorized/3c9b63524d57492b265454f62d895f71
        vm.etch(0x000000000000378eDCD5B5B0A24f5342d8C10485, hex'483d52593df3');

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

    function test_isValidSignature_Vanilla1271_TypedData_RPC() public {
        // do not add safe sender
        bytes32 dataToSign = hashTypedDataSecure(Mail({from: address(1), to: address(2), contents: "Moo!"}), instance.account);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, dataToSign);
        bytes memory signature = abi.encodePacked(address(validator), r, s, v);

        vm.txGasPrice(0);
        (bool success, bytes memory res) = instance.account.call{gas: 5_000_000}(abi.encodeWithSelector(IERC7579Account.isValidSignature.selector, dataToSign, signature));
        assertEq(bytes4(res), bytes4(0x1626ba7e));
    }

    // ===== HELPERS ======

    struct Mail {
        address from;
        address to;
        string contents;
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
}
