// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SLVToken is ERC20 {
    uint256 private countA;
    uint256 private countB;

    constructor() ERC20("Silver", "SLV") {}

    function incrementCountA() public {
      countA = countA + 1;
    }

    function incrementCountB() public {
      countB = countB + 1;
    }

    receive() external payable {}

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}
