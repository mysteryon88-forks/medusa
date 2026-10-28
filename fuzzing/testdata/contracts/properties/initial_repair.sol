contract TestContract {
    bool private ready;

    function repair() external { ready = true; }
    function property_ready() external view returns (bool) { return ready; }
}
