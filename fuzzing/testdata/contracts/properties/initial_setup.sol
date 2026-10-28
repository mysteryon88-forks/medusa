contract TestContract {
    bool private ready;

    function touch() external {}
    function property_ready() external view returns (bool) { return ready; }
}
