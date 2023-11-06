# Example website

Note that the example webserver cannot read the files
in this directory.  It only reads the `resources.toit`
file.  Every time you have changed the files in this
directory you must rerun the `make.sh` file to copy the
files into the `resources.toit` file.

In text-based formats you can use {{substitution}} to
allow the example server to insert dynamic content.
Customize this behaviour in the `look-up-variable`
function.

The WiFi logo, wifi-svgrepo.com.svg is from
https://www.svgrepo.com/svg/112855/wifi where it has a CC0 license.
