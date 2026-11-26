"""Entry point for the frozen Panoptes.exe desktop app."""
import multiprocessing

from panoptes.gui.app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
