// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SLVToken is ERC20 {
    uint256 private countA;
    uint256 private countB;

    constructor() ERC20("Silver", "SLV") {
        /* _mint(address(this), 1); */
    }

    function incrementCountA() public {
      countA = countA + 1;
    }

    function incrementCountB() public {
      countB = countB + 1;
    }

    receive() external payable {}

    function destroy() public {
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");

        /* _burn(address(this), balanceOf(address(this))); */
    }
}
