pragma solidity ^0.8.0;

contract VerifySig{


    function verify(address _signer,string memory _message,bytes memory _sig) external pure returns(bool){

        bytes32 messageHash = getMessageHash(_message);
        bytes32 _ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(_ethSignedMessageHash,_sig) == _signer;
    }
    
    function getMessageHash(string memory _message)public pure returns(bytes32){
        return keccak256(abi.encodePacked(_message));
    }

    function getEthSignedMessageHash(bytes32 _messageHash)public pure returns(bytes32){
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messageHash));
        /* This ensures that the signature cannot be used for purposes outside of Ethereum. */
    }


    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = _split(_sig); //values for the transaction's signature
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function _split(bytes memory _sig) internal pure returns (bytes32 r,bytes32 s,uint8 v){
        require(_sig.length == 65," ");

        assembly{
            r:= mload(add(_sig,32))
            s:= mload(add(_sig,64))
            v:= byte(0,mload(add(_sig,96)))
        }

        return(r ,s ,v);
    }
}

