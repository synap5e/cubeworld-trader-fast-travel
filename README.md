cubeworld-trader-fast-travel
============================

This mod for CubeWorld enables fast-travel between discovered cities by joining traders caravans from city to city (caravans not shown).

Trader stands gain the action '[R] Travel to ...' action, with different stands allowing travel to discovered cities (the cities must have been discovered while the modded version was running).

If you have not discovered any other cities (with the mod running) than the city you are in then the action will be '[R] Travel' but you will be informed that you cannot travel to undiscovered cities.
Cities are marked as discoevered based on the map seed, so cities discovered by another character on the same map, or even on a different map with the same seed will be valid targets.

Installing
--------

This mod requires the x86 version of [Visual C++ Redistributable for Visual Studio 2013 Preview](www.microsoft.com/download/details.aspx?id=39315)

Download the latest release from [here](https://github.com/synap5e/cubeworld-trader-fast-travel/releases), unzip and place the files in the CubeWorld folder (`C:/Program Files (x86)/CubeWorld` or `C:/Program Files/CubeWorld`).
Launch by running `TraderFastTravelModLauncher.exe`

If you do not want the town-portal spell, do not copy (or delete) the KeyEvent.dll


Sharing city locations
--------

The mod creates `word-<seed>.sav` files in the CubeWorld directory that you can share to import extra city locations.


Uninstalling
--------

If you want to run CubeWorld without this mod, just launch with the original launcher

Thanks
-------

LUDIJAK: Code for the launcher and some functions in the mod.
