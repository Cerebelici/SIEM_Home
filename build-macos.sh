cd /Users/admin/projects/cerberus/front && npm run build && \
cp -r dist/* ../desktop/frontend/dist/ && \
cd ../desktop && wails build -platform darwin/universal -clean && \
bash packaging/darwin/build-dmg.sh ../Cerberus-macOS-universal.dmg && \
cd ..