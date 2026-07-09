#!/bin/bash
set -e

. "$HOME/.cargo/env"

cd
git clone https://github.com/helix-editor/helix.git
cd helix
git checkout a05c151

# install helix
HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 cargo install --path helix-term --locked

# copy over remaining runtime files
mkdir ~/.config/helix
cp -r runtime/ ~/.config/helix/runtime/

# manually build grammars because there is an issue with go on this version
echo 'use-grammars = { except = [ "go", "gomod", "gotmpl", "gowork" ] }' >> ~/.config/helix/languages.toml
hx --grammar fetch
hx --grammar build

# set default theme
echo 'theme = "onedark"' >> ~/.config/helix/config.toml

# remove downloaded repo
cd ..
rm -rf helix

