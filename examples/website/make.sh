#!/bin/sh

# Creates resources.toit from the image files in this directory.
# All files found here (with known suffixes) are put in the compiled
#   Toit program, so you can save space by removing them from this directory if
#   they are unused

# Requires Posix tools like hexdump, tr, and sed.

# Exit on errors.
set -e

# Correct behaviour if there is no match for some of the file suffixes.
shopt -s nullglob

cat resources.toit.header > resources.toit

# Binary files are turned into ByteArrays.
# We normally expect only lower case suffixes, but cameras seem to make upper
#   case JPG files.
# Note that the web server does not decompress compressed files, this is
#   done by the browser.  A consequence of this is that the {{}} substitution
#   is not performed on compressed files.
for filename in *.{png,jpg,JPG,jpeg,JPEG,png.br,css.br,html.br,svg.br,css.gz,html.gz,svg.gz}
do
    echo                                                                    >> resources.toit
    echo "/// Autogenerated from $filename."                                >> resources.toit
    echo -n $filename | sed 's/\.[a-z]\+\(\.br\|\.gz\)\?$//' | tr a-z- A-Z_ >> resources.toit
    echo " ::= #["                                                          >> resources.toit
    hexdump -ve '"  " 12/1 "0x%02x, " "\n"' $filename | sed 's/, 0x  //g'   >> resources.toit
    echo "]"                                                                >> resources.toit
done

# Text files are turned into strings.
for filename in *.{css,html,svg}
do
    echo                                                                    >> resources.toit
    echo "/// Autogenerated from $filename."                                >> resources.toit
    echo -n $filename | sed 's/\.[a-z]\+$//' | tr a-z- A-Z_                 >> resources.toit
    echo ' ::= """'                                                         >> resources.toit
    sed 's/\r//g' $filename                                                 >> resources.toit
    echo '"""'                                                              >> resources.toit
done


echo ""                                                                     >> resources.toit
echo "RESOURCE_MAP ::= {"                                                   >> resources.toit
for filename in *.{png,jpg,JPG,jpeg,JPEG,css,html,svg,png.br,css.br,html.br,svg.br,css.gz,html.gz,svg.gz}
do
    echo -n "  \"$filename\": "                                             >> resources.toit
    echo "$filename" | sed 's/\.[a-z]\+\(\.br\|\.gz\)\?$/,/' | tr a-z- A-Z_ >> resources.toit
done
echo "}"                                                                    >> resources.toit
