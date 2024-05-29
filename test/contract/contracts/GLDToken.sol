pragma solidity ^0.8.25;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract GLDToken is ERC20 {
    constructor() ERC20("Gold", "GLD") {
        _mint(msg.sender, 1000000000000000000000);
    }

    function destroy() public {
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");

        _burn(msg.sender, balanceOf(msg.sender));
    }
}
