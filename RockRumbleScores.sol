// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

//    (`-')                      <-.(`-')        (`-')            <-. (`-')  <-.(`-')           (`-')  _ 
// <-.(OO )      .->    _         __( OO)     <-.(OO )      .->      \(OO )_  __( OO)    <-.    ( OO).-/ 
// ,------,)(`-')----.  \-,-----.'-'. ,--.    ,------,),--.(,--.  ,--./  ,-.)'-'---.\  ,--. )  (,------. 
// |   /`. '( OO).-.  '  |  .--./|  .'   /    |   /`. '|  | |(`-')|   `.'   || .-. (/  |  (`-') |  .---' 
// |  |_.' |( _) | |  | /_) (`-')|      /)    |  |_.' ||  | |(OO )|  |'.'|  || '-' `.) |  |OO )(|  '--.  
// |  .   .' \|  |)|  | ||  |OO )|  .   '     |  .   .'|  | | |  \|  |   |  || /`'.  |(|  '__ | |  .--'  
// |  |\  \   '  '-'  '(_'  '--'\|  |\   \    |  |\  \ \  '-'(_ .'|  |   |  || '--'  / |     |' |  `---. 
// `--' '--'   `-----'    `-----'`--' '--'    `--' '--' `-----'   `--'   `--'`------'  `-----'  `------'

/// @title Rock Rumble Scores Contract
/// @author Sneakz
/// @notice This contract holds functions used for the Rock Rumble game
/// @dev All function calls are tested and have been implemented on the Rock Rumble Game

contract RockRumbleScores is ReentrancyGuard {

    /// @dev Mappings & state variables

    /// @dev Wallet that auth signatures come from
    address authWallet = 0x0d9566FcE2513cBD388DCD7749a873900033401C;
    /// @dev Mod wallet for resets
    address modWallet = 0xb74C9e663914722914b9D7AeE3C26eD2A94261e6;
    /// @dev Mapping for user wallets with scores
    mapping(uint256 => address) public userWalletScores;
    /// @dev Array for user wallet scores
    address[] public userWallets;
    uint256[] public userScores;

    /// @dev Events

    event SaveScore(address indexed wallet, uint256 _amount);
    event ResetScores(address indexed wallet);

    /// @dev Functions

    /// @notice Saves a users score
    /// @param _score The score to save
    /// @return true if successful
    function saveScore(uint _score, bytes memory _sig) external nonReentrant() returns (bool) {
        bytes32 messageHash = getMessageHash(Strings.toString(_score));
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        require(recover(ethSignedMessageHash, _sig) == authWallet, "Sig not made by auth");
        // Add score to wallet mapping
        userWalletScores[_score] = msg.sender;
        // Add wallet to wallet array
        userWallets.push(msg.sender);
        // Add score to score array
        userScores.push(_score);
        // Sort scores array
        uint length = userScores.length;
            for (uint i = 0; i < length; i++) {
                uint key = userScores[i];
                int j = int(i) - 1;
                while ((int(j) >= 0) && (userScores[uint(j)] > key)) {
                    userScores[uint(j + 1)] = userScores[uint(j)];
                    j--;
                }
                userScores[uint(j + 1)] = key;
            }
        emit SaveScore(msg.sender, _score);
        return true;
    }

    /// @notice Resets user scores
    /// @return true if successful
    function resetScores() external nonReentrant() returns (bool) {
        require(msg.sender == modWallet, "Only mods can do this");
        // Reset wallet array
        delete userWallets;
         /// Removes wallet mappings
        for (uint256 x = 0; x < userScores.length; ++x) {
            delete userWalletScores[userScores[x]];
        }
        // Reset score array
        delete userScores;
        emit ResetScores(msg.sender);
        return true;
    }

    /// @dev Used for ECDSA verification to check if values came from inside the Rock Rumble game following solidity standards
    function VerifySig(address _signer, string memory _message, bytes memory _sig) external pure returns (bool) {
        bytes32 messageHash = getMessageHash(_message);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return recover(ethSignedMessageHash, _sig) == _signer;
    }

    function getMessageHash(string memory _message) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_message));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messageHash));
    }

    function recover(bytes32 _ethSignedMessageHash, bytes memory _sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function _split (bytes memory _sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
    }
}