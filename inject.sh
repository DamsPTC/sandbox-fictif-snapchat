#!/bin/bash
# Produit une COPIE à resigner. L'IPA d'entrée reste intacte.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    printf '%s\n' 'Usage: bash inject.sh input.ipa QAIdentity.dylib output.ipa' >&2
    exit 2
fi
for qa_tool in xcrun ditto zip; do
    command -v "$qa_tool" >/dev/null 2>&1 || {
        printf 'Commande manquante : %s\n' "$qa_tool" >&2; exit 1;
    }
done
QA_INSERT="${INSERT_DYLIB:-insert_dylib}"
command -v "$QA_INSERT" >/dev/null 2>&1 || {
    printf '%s\n' 'Installer insert_dylib ou définir INSERT_DYLIB avec son chemin absolu.' >&2
    exit 1
}
[[ -f "$1" && -f "$2" ]] || { printf '%s\n' 'IPA ou dylib introuvable.' >&2; exit 1; }
[[ ! -e "$3" ]] || { printf '%s\n' 'Le fichier de sortie existe déjà.' >&2; exit 1; }

QA_INPUT="$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")"
QA_LIBRARY="$(cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")"
QA_OUTPUT="$(cd -- "$(dirname -- "$3")" && pwd)/$(basename -- "$3")"

QA_WORK="$(mktemp -d "$PWD/qaipa.XXXXXX")"
# Ce dossier est conservé pour permettre une signature manuelle après injection.
printf 'Dossier de travail : %s\n' "$QA_WORK"
ditto -x -k "$QA_INPUT" "$QA_WORK"
shopt -s nullglob
qa_apps=("$QA_WORK"/Payload/*.app)
[[ ${#qa_apps[@]} -eq 1 ]] || { printf '%s\n' 'Une seule app principale est attendue.' >&2; exit 1; }
QA_APP="${qa_apps[0]}"
QA_PLIST="$QA_APP/Info.plist"
QA_EXEC="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$QA_PLIST")"
[[ -n "$QA_EXEC" && "$QA_EXEC" != */* && "$QA_EXEC" != . && "$QA_EXEC" != .. ]] || {
    printf '%s\n' 'CFBundleExecutable invalide.' >&2; exit 1;
}
QA_BINARY="$QA_APP/$QA_EXEC"
xcrun lipo "$QA_BINARY" -verify_arch arm64
xcrun lipo "$QA_LIBRARY" -verify_arch arm64
xcrun otool -l "$QA_BINARY" > "$QA_WORK/main-load-commands.txt"
if awk '$1 == "cryptid" && $2 != "0" { found=1 } END { exit !found }' "$QA_WORK/main-load-commands.txt"; then
    printf '%s\n' 'Binaire déclaré chiffré : utiliser un export de développement non chiffré.' >&2
    exit 1
fi

QA_LOAD_PATH='@executable_path/Frameworks/QAIdentity.dylib'
xcrun otool -L "$QA_BINARY" > "$QA_WORK/main-dependencies-before.txt"
if awk '$1 == "@executable_path/Frameworks/QAIdentity.dylib" { found=1 } END { exit !found }' "$QA_WORK/main-dependencies-before.txt"; then
    printf '%s\n' 'QAIdentity est déjà injecté. Repartir de l’IPA d’origine.' >&2
    exit 1
fi
mkdir -p "$QA_APP/Frameworks"
[[ ! -e "$QA_APP/Frameworks/QAIdentity.dylib" ]] || {
    printf '%s\n' 'Un fichier QAIdentity.dylib est déjà présent.' >&2; exit 1;
}
cp "$QA_LIBRARY" "$QA_APP/Frameworks/QAIdentity.dylib"

/usr/libexec/PlistBuddy -c 'Set :QAIdentityEnabled true' "$QA_PLIST" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c 'Add :QAIdentityEnabled bool true' "$QA_PLIST"

"$QA_INSERT" --inplace --strip-codesig --all-yes "$QA_LOAD_PATH" "$QA_BINARY"
xcrun otool -L "$QA_BINARY" > "$QA_WORK/main-dependencies-after.txt"
awk '$1 == "@executable_path/Frameworks/QAIdentity.dylib" { found=1 } END { exit !found }' "$QA_WORK/main-dependencies-after.txt"
(
    cd "$QA_WORK"
    COPYFILE_DISABLE=1 zip -qry "$QA_OUTPUT" Payload
)
printf 'IPA préparée, À RESIGNER ENTIÈREMENT : %s\n' "$QA_OUTPUT"
printf 'App extraite : %s\n' "$QA_APP"
