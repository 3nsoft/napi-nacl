for target in $(cat package.json | jq -r .napi.targets[])
do
  echo "-----------------------------------------------"
  echo "|  compiling for $target"
  echo "-----------------------------------------------"
  npm run compile-napi -- --cross-compile --target $target || exit $?
  echo
done
