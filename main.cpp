auto main(int argc, char* argv[]) -> int {

    std::cout << R"(

DROP OUT

)" << std::endl;

    if (argc != 2) {
        std::cout << "[!] Usage: " << argv[0] << " <PID>\n";
        return 1;
    }

    if (!::IsUserAnAdmin()) {
        std::cout << "[X] Must run as Administrator!\n";
        return 1;
    }

    DWORD dwPid = 0;
    try {
        dwPid = std::stoul(argv[1]);
    } catch (...) {
        std::cout << "[X] Invalid PID input!\n";
        return 1;
    }

    DropOut dropOut;
    dropOut.KillProcessByPID(dwPid);

    std::cout << "[!] Press Enter to cleanup...\n";
    std::cin.get();

    return 0;
}
