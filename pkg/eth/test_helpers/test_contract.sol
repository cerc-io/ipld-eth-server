pragma solidity ^0.5.10;

contract test {
    address payable owner;

    modifier onlyOwner {
        require(
            msg.sender == owner,
            "Only owner can call this function."
        );
        _;
    }

    uint256 public data;

    constructor() public {
        owner = msg.sender;
        data = 1;
    }

    function Put(uint256 value) public {
        data = value;
    }

    function close() public onlyOwner {
        selfdestruct(owner);
    }
}