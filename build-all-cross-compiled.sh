for target in $(cat package.json | jq -r .napi.targets[])
do
  echo "-----------------------------------------------"
  echo "|  compiling for $target"
  echo "-----------------------------------------------"
  npm run build -- --cross-compile --target $target || exit $?
  echo
done

echo "-----------------------"
echo "|  Patching index.js  |"
echo "-----------------------"

node -e "
let jsCode = fs.readFileSync('index.js', 'utf-8');
jsCode = jsCode.replaceAll(\"require('./napi-nacl.linux-\", \"require(__dirname+'/napi-nacl.linux-\");
fs.writeFileSync('index.js', jsCode);
" || exit $?