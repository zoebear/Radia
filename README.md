# Radia

Radia is a tool designed to create an interactive and immerse environment to visualize code, and to augment the task of reverse engineering binaries. The tool takes decompiled binaries extracted through IDA Pro, and visualizes the call graph in 3D space as a force directed graph. Radia tags functions that could be potential problems, as well as giving the user specific insight into individual nodes and their contents and relationships to other functions. In the end, the hope is to improve the available tools for auditing code to readily identify and remediate problems, and ultimately, to make code less vulnerable to exploitation by malware.

Radia was built as my thesis project in Interaction Design. For further details about the project see [Zoe Hardisty Design].(http://www.zoehardistydesign.com)

Please contact me at zoe [dot] hardisty [at] gmail.com if you are interested in expanding this project especially if you would like design to be a part of it.

##Code

Included is the script to export binaries out of IDA Pro idapy_radia.py, a sample file of the exported radia.json, and the Unity project containing Radia and the build files. The JSON file is currently pointed to in the GameController.cs file till a dialog box can be written for the Main Menu screen.

Requires Unity 5 to edit files, and IDA Pro to export content.

##Fonts Used In Radia

In the creation of this project as a student work I used a few fonts within the application as text and as images. To develop this software further would require the individual or group to obtain their own application licenses for these fonts or change them. The following information has been provided to allow these fonts to be used responsibly and in accordance to the licensing from their creators.

####Main Font

*Bender* by Jovanny Lemonad
[Font Squirrel - Bender](http://www.fontsquirrel.com/fonts/Bender),
[License Used](http://www.fontsquirrel.com/license/Bender)
(designer should be contacted to buy the appropriate licence)

####Microcopy Font

*Supermolot Light* by TypeType - Used for microcopy on start menu.
[MyFonts - Supermolot](http://www.myfonts.com/fonts/type-type/supermolot/buy.html).
The Font Software for Mobile Applications End User License Agreement should be purchased for this font.

####Monospace Font

*Ubuntu Mono Bold*
[Ubuntu Font](http://font.ubuntu.com),
[Font Licence](http://font.ubuntu.com/licence/)
