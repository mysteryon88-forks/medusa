contract TestContract {
    function property_false() external pure returns (bool) { return false; }
}

contract InitialTrue {
    function property_true() external pure returns (bool) { return true; }
}

contract InitialMany {
    function property_a() external pure returns (bool) { return false; }
    function property_b() external pure returns (bool) { return false; }
}

contract InitialRevert {
    function property_revert() external pure returns (bool) { revert("not ready"); }
}

contract InitialMalformed {
	function touch() external {}
    function property_bad() external pure returns (bool) { assembly { return(0, 0) } }
}
