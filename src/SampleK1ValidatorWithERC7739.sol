// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC7739Validator } from "./ERC7739Validator.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { EnumerableSet } from "enumerableset4337/EnumerableSet4337.sol";
import { ModuleInstallLib } from "./utils/ModuleInstallLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SampleK1ValidatorWithERC7739 is ERC7579ValidatorBase, ERC7739Validator {

    using SignatureCheckerLib for address;
    using EnumerableSet for EnumerableSet.AddressSet;
    using ModuleInstallLib for bytes;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    uint256 constant ERC7579_MODULE_TYPE_STATELESS_VALIDATOR = 7;

    /// @notice Mapping of smart account addresses to their respective owner addresses
    mapping(address => address) public smartAccountOwners;

    EnumerableSet.AddressSet private safeSenders;

    /// @notice Error to indicate that no owner was provided during installation
    error NoOwnerProvided();

    /// @notice Error to indicate that the new owner cannot be the zero address
    error ZeroAddressNotAllowed();

    /// @notice Error to indicate the module is already initialized
    error ModuleAlreadyInitialized();

    /// @notice Error to indicate that the new owner cannot be a contract address
    error NewOwnerIsContract();

    /// @notice Error to indicate that the data length is invalid
    error InvalidDataLength();


    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        require(data.length != 0, NoOwnerProvided());
        require(!_isInitialized(msg.sender), ModuleAlreadyInitialized());
        if(data.asValidator()) {
            address newOwner = address(bytes20(data[1:21]));
            require(!_isContract(newOwner), NewOwnerIsContract());
            smartAccountOwners[msg.sender] = newOwner;
            if (data.length > 21) {
                _fillSafeSenders(data[21:]);
            }
        }
    }

    /**
     * De-initialize the module with the given data
     *
     * @param data The data to de-initialize the module with
     */
    function onUninstall(bytes calldata data) external override {
        if(data.asValidator()) {
            delete smartAccountOwners[msg.sender];
            safeSenders.removeAll(msg.sender);
        }
    }

    /**
     * Check if the module is initialized
     * @param smartAccount The smart account to check
     *
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    /// @notice Transfers ownership of the validator to a new owner
    /// @param newOwner The address of the new owner
    function transferOwnership(address newOwner) external {
        require(newOwner != address(0), ZeroAddressNotAllowed());
        require(!_isContract(newOwner), NewOwnerIsContract());
        smartAccountOwners[msg.sender] = newOwner;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates PackedUserOperation
     *
     * @param userOp UserOperation to be validated
     * @param userOpHash Hash of the UserOperation to be validated
     *
     * @return uint256 the result of the signature validation, which can be:
     *  - 0 if the signature is valid
     *  - 1 if the signature is invalid
     *  - <20-byte> aggregatorOrSigFail, <6-byte> validUntil and <6-byte> validAfter (see ERC-4337
     * for more details)
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view override returns (ValidationData) {
        return _validateSignatureForOwner(smartAccountOwners[userOp.sender], userOpHash, userOp.signature) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /**
     * Validates an ERC-1271 signature
     *
     * @param sender The sender of the ERC-1271 call to the account
     * @param hash The hash of the message
     * @param signature The signature of the message
     *
     * @return sigValidationResult the result of the signature validation, which can be:
     *  - EIP1271_SUCCESS if the signature is valid
     *  - EIP1271_FAILED if the signature is invalid
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        virtual
        override
        returns (bytes4)
    {   
        return _erc1271IsValidSignatureWithSender(sender, hash, signature);
    }

    /// @notice ISessionValidator interface for smart session
    /// @param hash The hash of the data to validate
    /// @param sig The signature data
    /// @param data The data to validate against (owner address in this case)
    function validateSignatureWithData(bytes32 hash, bytes calldata sig, bytes calldata data) external view returns (bool validSig) {
        require(data.length == 20, InvalidDataLength());
        address owner = address(bytes20(data[0:20]));
        return _validateSignatureForOwner(owner, hash, sig);
    }

    /// @notice Adds a safe sender to the safeSenders list for the smart account
    function addSafeSender(address sender) external {
        safeSenders.add(msg.sender, sender);
    }

    /// @notice Removes a safe sender from the safeSenders list for the smart account
    function removeSafeSender(address sender) external {
        safeSenders.remove(msg.sender, sender);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Returns whether the `hash` and `signature` are valid.
    ///      Obtains the authorized signer's credentials and calls some
    ///      module's specific internal function to validate the signature
    ///      against credentials.
    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool) 
    {
        // obtain credentials
        address owner = smartAccountOwners[msg.sender];

        // call custom internal function to validate the signature against credentials
        return _validateSignatureForOwner(owner, hash, signature);
    }

    /// @dev Returns whether the `sender` is considered safe, such
    /// that we don't need to use the nested EIP-712 workflow.
    /// See: https://mirror.xyz/curiousapple.eth/pFqAdW2LiJ-6S4sg_u1z08k4vK6BCJ33LcyXpnNb8yU
    // The canonical `MulticallerWithSigner` at 0x000000000000D9ECebf3C23529de49815Dac1c4c
    // is known to include the account in the hash to be signed.
    // msg.sender = Smart Account
    // sender = 1271 og request sender        
    function _erc1271CallerIsSafe(address sender) internal view virtual override returns (bool) {
        return ( 
                    sender == 0x000000000000D9ECebf3C23529de49815Dac1c4c || // MulticallerWithSigner
                    safeSenders.contains(msg.sender, sender) // check if sender is in safeSenders for the Smart Account
                );
    }
   
    /// @notice Internal method that does the job of validating the signature via ECDSA (secp256k1)
    /// @param owner The address of the owner
    /// @param hash The hash of the data to validate
    /// @param signature The signature data
    function _validateSignatureForOwner(address owner, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        // Check if the 's' value is valid
        bytes32 s;
        assembly {
            // same as `s := mload(add(signature, 0x40))` but for calldata
            s := calldataload(add(signature.offset, 0x20))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }

        if (SignatureCheckerLib.isValidSignatureNowCalldata(owner, hash, signature)) {
            return true;
        }
        if (SignatureCheckerLib.isValidSignatureNowCalldata(owner, MessageHashUtils.toEthSignedMessageHash(hash), signature)) {
            return true;
        }
        return false;
    }

    /// @notice Checks if the smart account is initialized with an owner
    /// @param smartAccount The address of the smart account
    /// @return True if the smart account has an owner, false otherwise
    function _isInitialized(address smartAccount) private view returns (bool) {
        return smartAccountOwners[smartAccount] != address(0);
    }

    /// @notice Checks if the address is a contract
    /// @param account The address to check
    /// @return True if the address is a contract, false otherwise
    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    // @notice Fills the safeSenders list from the given data
    function _fillSafeSenders(bytes calldata data) private {
        for (uint256 i; i < data.length / 20; i++) {
            safeSenders.add(msg.sender, address(bytes20(data[20*i:20*(i+1)])));
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * The name of the module
     *
     * @return name The name of the module
     */
    function name() external pure returns (string memory) {
        return "Sample ERC7739 enabled Validator";
    }

    /**
     * The version of the module
     *
     * @return version The version of the module
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * Check if the module is of a certain type
     *
     * @param typeId The type ID to check
     *
     * @return true if the module is of the given type, false otherwise
     */
    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == TYPE_VALIDATOR || typeId == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR;
    }
}
