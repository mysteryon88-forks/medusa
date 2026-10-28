interface CheatCodes {
    function warp(uint256) external view;
    function roll(uint256) external view;
    function fee(uint256) external view;
    function coinbase(address) external view;
    function chainId(uint256) external view;
    function label(address, string calldata) external view;
    function store(address, bytes32, bytes32) external view;
    function snapshot() external view returns (uint256);
    function revertTo(uint256) external view returns (bool);
    function ffi(string[] calldata) external view returns (bytes memory);
}

contract TestContract {
    CheatCodes constant cheats = CheatCodes(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function property_initial() external view returns (bool) {
        cheats.warp(12345);
        return false;
    }

    function checkIsolation() external view returns (bool) {
        cheats.warp(12345);
        cheats.roll(10);
        cheats.fee(7);
        cheats.coinbase(address(0x1234));
        cheats.chainId(42);
        cheats.label(address(this), "temporary");
        cheats.store(address(this), bytes32(0), bytes32(uint256(1)));
        cheats.snapshot();
        return block.timestamp == 12345 && block.number == 10 && block.basefee == 7
            && block.coinbase == address(0x1234) && block.chainid == 42;
    }

    function checkCaughtRevert() external view returns (bool) {
        try cheats.revertTo(0) returns (bool) {} catch {}
        return true;
    }

    function checkCaughtFFI() external view returns (bool) {
        string[] memory command = new string[](0);
        try cheats.ffi(command) returns (bytes memory) {} catch {}
        return true;
    }
}
