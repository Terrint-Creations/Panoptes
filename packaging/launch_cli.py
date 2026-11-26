"""Entry point for the frozen panoptes-cli.exe terminal tool."""
import multiprocessing

from panoptes.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
