
# Read the docs: https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html#scriptPath
GHIDRA_PATH=~/Desktop/ghidra_9.1.2_PUBLIC/support/
GHIDRA_PROJECTS=~/Desktop/ghidra
GHIDRA_SCRIPTS=./

# Import binary to project
$GHIDRA_PATH/analyzeHeadless $GHIDRA_PROJECTS ProjectDataset/folderOne \
    -scriptPath "$GHIDRA_SCRIPTS" \
    -import $2 \
    -postScript $1 \
    -readOnly
