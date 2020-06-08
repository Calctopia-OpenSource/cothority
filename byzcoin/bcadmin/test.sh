#!/usr/bin/env bash

# Usage: 
#   ./test [options]
# Options:
#   -b   re-builds bcadmin package

DBG_TEST=1
DBG_SRV=1
DBG_BCADMIN=2

NBR_SERVERS=4
NBR_SERVERS_GROUP=3

# Clears some env. variables
export -n BC_CONFIG
export -n BC
export BC_WAIT=true

. "../../libtest.sh"
. "../clicontracts/config_test.sh"
. "../clicontracts/deferred_test.sh"
. "../clicontracts/value_test.sh"
. "../clicontracts/name_test.sh"

main(){
    startTest
    buildConode go.dedis.ch/cothority/v3/byzcoin go.dedis.ch/cothority/v3/byzcoin/contracts
    [[ ! -x ./bcadmin ]] && exit 1
    run testReset
    run testDbReplay
    run testDbMerge
    run testDbCatchup
    run testDebugBlock
    run testLink
    run testLinkScenario
    run testCoin
    run testRoster
    run testCreateStoreRead
    run testAddDarc
    run testDarcAddDeferred
    run testDarcAddRuleMinimum
    run testRuleDarc
    run testAddDarcFromOtherOne
    run testAddDarcWithOwner
    run testExpression
    run testLinkPermission
    run testQR
    run testUpdateDarcDesc
    run testResolveiid
    run testInstructionGet
    run testContractValue
    run testContractDeferred
    run testContractConfig
    run testContractName
    stopTest
}

# TODO: https://github.com/dedis/cothority/issues/2150
testReset(){
  rm -f config/* *.db
  runCoBG 1 2 3
  runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  db=service_storage/$( ls service_storage | tail -n 1 )
  runBA config --blockSize 1000000 $bc $key

  pkill -9 conode
  testFail runBA db resetBlock $db $bcID
}

testDbReplay(){
  rm -f config/* *.db
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  keyPub=$( echo $key | sed -e "s/.*:\(.*\).cfg/\1/" )

  testFail runBA db replay conode.db $bcID
  testOK runBA db catchup conode.db $bcID http://localhost:2003
  testGrep "Replaying block at index 0" runBA0 db replay conode.db $bcID

  # replay with more than 1 block
  testOK runBA mint $bc $key $keyPub 1000
  testOK runBA mint $bc $key $keyPub 1000
  runBA db catchup conode.db $bcID http://localhost:2003
  testGrep "Replaying block at index 0" runBA0 db replay conode.db $bcID
  testGrep "index 0" runBA0 db replay conode.db $bcID --write --blocks 1
  testReNGrep "index 1"
  testNGrep "index 0" runBA0 db replay conode.db $bcID --write --continue
  testReGrep "index 1"
}

testDbMerge(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  keyPub=$( echo $key | sed -e "s/.*:\(.*\).cfg/\1/" )

  db=$( ls $CONODE_SERVICE_PATH/* | head -n 1 )
  pkill conode 2> /dev/null

  testOK runBA db merge conode.db $bcID $db
  testGrep "Last block is: 0" runBA0 db status conode.db $bcID

  runCoBG 1 2 3
  testOK runBA mint $bc $key $keyPub 1000

  pkill conode 2> /dev/null
  testOK runBA db merge conode.db $bcID $db
  testGrep "Last block is: 3" runBA0 db status conode.db $bcID
}

testDbCatchup(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  keyPub=$( echo $key | sed -e "s/.*:\(.*\).cfg/\1/" )

  testOK runBA db catchup conode.db $bcID http://localhost:2003
  testGrep "Last block is: 0" runBA0 db status conode.db $bcID
  testOK runBA mint $bc $key $keyPub 1000
  testOK runBA db catchup conode.db $bcID http://localhost:2003
  testGrep "Last block is: 3" runBA0 db status conode.db $bcID
}

testDebugBlock(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  keyPub=$( echo $key | sed -e "s/.*:\(.*\).cfg/\1/" )

  testOK runBA debug block --bcCfg $bc --blockIndex 0
  testGrep "no block with index" runBA0 debug block --bcCfg $bc --blockIndex 1
  runBA config --blockSize 1000000 $bc $key
  testNGrep "no block with index" runBA0 debug block --bcCfg $bc --blockIndex 1
  testNGrep "no block with index" runBA0 debug block \
    --url http://localhost:2003 --bcID $bcID --blockIndex 1
  testGrep "Command: update_config" runBA0 debug block --bcCfg $bc \
    --blockIndex 1 --txDetails
}

testLink(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  runBA key --save newkey.id
  testOK runBA darc add --bc $bc --id $( cat newkey.id ) --out_id darc.id

  rm -rf linkDir
  bcID=$( echo $bc | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  testGrep $bcID runBA0 -c linkDir link public.toml
  bcIDWrong=$( printf "%032d" 1234 )
  testNGrep $bcIDWrong runBA0 -c linkDir link public.toml
  testFail runBA -c linkDir link public.toml $bcIDWrong
  testOK runBA -c linkDir link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  # should fail since it would overwrite the file
  testFail runBA -c linkDir link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  # should pass with the --force option
  testOK runBA -c linkDir link --force --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID

  testFile linkDir/bc*
}

# This is a complete scenario with link that uses the value clicontract.
# We create a new client and a new associated darc that is allowed to call
# "spawn:value". We first need to specify --darc and --sign to use the value
# contract. But then we link to the client and its darc, which will then use
# by default the client's identity and darc.
testLinkScenario(){
  rm -f config/*
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1
  rm -rf linkDir

  # Create new client
  runBA key --save newkey.id
  # Create new darc for the client
  testOK runBA darc add --id $( cat newkey.id ) --out_id darc.id --unrestricted

  # Try to spawn a new value contract with the client's darc. It should fail
  # since we did not add the rule
  testFail runBA contract value spawn --value "should fail" --darc $( cat darc.id ) --sign $( cat newkey.id )

  # Update the client darc so that it can spawn:value new contracts
  testOK runBA darc rule --rule "spawn:value" --identity $( cat newkey.id ) --sign $( cat newkey.id ) --darc $( cat darc.id )

  # Try to spawn again, should work this time
  testOK runBA contract value spawn --value "shoudl fail" --darc $( cat darc.id ) --sign $( cat newkey.id )

  # Now if we don't specify any --darc and --sign, it will use the admin darc,
  # which should fail since it doesn't have the rule
  testFail runBA contract value spawn --value "should fail"

  # Let's try now to link with the client darc and identity. This will make that
  # default --darc and --sign will be the client's darc and identiity
  bcID=$( echo $BC | sed -e "s/.*bc-\(.*\).cfg/\1/" )
  testOK runBA -c linkDir link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  # See if we can overwrite it withtout --force
  testFail runBA -c linkDir link --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID
  # Now we should be able to overwrite
  testOK runBA -c linkDir link --force --darc $( cat darc.id ) --identity $( cat newkey.id ) public.toml $bcID

  # The final test
  newBc="linkDir/$(ls linkDir | head -1)"
  testOK runBA contract value spawn --value "shoud pass" --bc "$newBc"

  testOK unset BC
}

testCoin(){
  rm -f config/*
  runCoBG 1 2 3
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  keyPub=$( echo $key | sed -e "s/.*key-ed25519:\(.*\).cfg/\1/" )
  testOK runBA mint $bc $key $keyPub 10000
}

testRoster(){
  rm -f config/*
  runCoBG 1 2 3 4
  testOK runBA create public.toml --interval .5s
  bc=config/bc*cfg
  key=config/key*cfg
  testOK runBA latest $bc

  # Adding an already added roster should raise an error
  testFail runBA roster add $bc $key co1/public.toml
  testOK runBA roster add $bc $key co4/public.toml
  runBA debug counters $bc $key
  testOK runBA config --blockSize 1000000 $bc $key
  testGrep 2008 runBA0 latest $bc

  testFail runBA roster add $bc $key co4/public.toml
  # Deleting the leader raises an error...
  testFail runBA roster del $bc $key co1/public.toml
  # ... but deleting someone else works
  testOK runBA roster del $bc $key co2/public.toml
  testNGrep "Roster:.*tls://localhost:2004" runBA0 latest $bc

  # Need at least 3 nodes to have a majority
  testFail runBA roster del $bc $key co3/public.toml
  # Adding a leader not in the roster raises an error
  testFail runBA roster leader $bc $key co2/public.toml
  # Setting a conode that is a leader as a leader raises an error
  testFail runBA roster leader $bc $key co1/public.toml
  testOK runBA roster leader $bc $key co3/public.toml
  testGrep "Roster: tls://localhost:2006" runBA0 latest -server 2 $bc
}


# When a conode is linked to a client (`scmgr link add ...`), it removes the
# possibility for 3rd parties to create a new skipchain on that conode. In the
# case a Bizcoin service hosted on a linked conode wants to adds a new
# skipchain, we have to bypass this authorization process and allow a local
# service be able to send requests on the same local linked conode. This process
# is handled with the `StoreSkipBlockInternal` method, and this is what this
# method checks. 
# Note: this test relies on the `scmgr` and the ability to create/update Byzcoin
testLinkPermission() {
  rm -f config/*
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1
  bc=config/bc*cfg
  key=config/key*cfg
  testOK runBA latest $bc
  build $APPDIR/../../scmgr
  SCMGR_APP="./scmgr"
  if [ ! -x $SCMGR_APP ]; then
    echo "Didn't find the \"scmgr\" executable at $SCMGR_APP"
    exit 1
  fi
  $SCMGR_APP link add co1/private.toml
  $SCMGR_APP link add co2/private.toml
  $SCMGR_APP link add co3/private.toml
  testOK runBA create --roster public.toml --interval .5s
  testOK runBA darc rule -rule spawn:xxx -identity ed25519:aef 
}


# create a ledger, and read the genesis darc.
testCreateStoreRead(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1
  bcid=`echo $BC | awk -F- '{print $2}'| sed 's/.cfg$//'`
  testGrep "ByzCoinID: $bcid" runBA0 latest
}

testAddDarc(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add
  testOK runBA darc add -out_id ./darc_id.txt
  testOK runBA darc add
  ID=`cat ./darc_id.txt`
  testGrep "${ID:5:${#ID}-0}" runBA0 darc show --darc "$ID"

  # checks the --shortPrint option
  OUTRES=$(runBA0 darc add --shortPrint)
  matchOK "$OUTRES" "darc:[0-9a-f]{64}
\[ed25519:[0-9a-f]{64}\]" 
}

testDarcAddDeferred() {
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  # standard stuff
  testOK runBA darc add -deferred
  testOK runBA darc add -deferred -out_id ./darc_id.txt
  testOK runBA darc add -deferred
  ID=`cat ./darc_id.txt`
  darc show --darc "$ID"
  testGrep "spawn:deferred" runBA0 darc show --darc "$ID"
  testGrep "invoke:deferred.addProof" runBA0 darc show --darc "$ID"
  testGrep "invoke:deferred.execProposedTx" runBA0 darc show --darc "$ID"

  # with minimum
  testOK runBA darc add -deferred -id darc:A -id ed25519:B -id darc:C -id darc:D -out_id ./darc_id.txt
  ID=`cat ./darc_id.txt`
  testFGrep "spawn:deferred - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:deferred.addProof - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:deferred.execProposedTx - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "_sign - \"darc:A & ed25519:B & darc:C & darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:darc.evolve - \"darc:A & ed25519:B & darc:C & darc:D\"" runBA0 darc show --darc "$ID"

  # with minimum, with unrestricted
  testOK runBA darc add -deferred -id darc:A -id ed25519:B -id darc:C -id darc:D -out_id ./darc_id.txt -unrestricted
  ID=`cat ./darc_id.txt`
  testFGrep "spawn:deferred - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:deferred.addProof - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:deferred.execProposedTx - \"darc:A | ed25519:B | darc:C | darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "_sign - \"darc:A & ed25519:B & darc:C & darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:darc.evolve - \"darc:A & ed25519:B & darc:C & darc:D\"" runBA0 darc show --darc "$ID"
  testFGrep "invoke:darc.evolve_unrestricted - \"darc:A & ed25519:B & darc:C & darc:D\"" runBA0 darc show --darc "$ID"
}

testDarcAddRuleMinimum(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  # With M out of N
  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id darc:A -id darc:B -id darc:C -id darc:D --minimum 1
  testFGrep "test:contract - \"((darc:A)) | ((darc:B)) | ((darc:C)) | ((darc:D))\"" runBA0 darc show --darc "$ID"
  
  # with a minimum
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id darc:A -id darc:B -id darc:C -id darc:D --minimum 2 -replace
  testFGrep "test:contract - \"((darc:A) & (darc:B)) | ((darc:A) & (darc:C)) | ((darc:A) & (darc:D)) | ((darc:B) & (darc:C)) | ((darc:B) & (darc:D)) | ((darc:C) & (darc:D))\"" runBA0 darc show --darc "$ID"

  # with a minimum and a special id composed of an AND
  testOK runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'darc:A & ed25519:aef' -id darc:B -id darc:C -id darc:D --minimum 2 -replace
  testFGrep "test:contract - \"((darc:A & ed25519:aef) & (darc:B)) | ((darc:A & ed25519:aef) & (darc:C)) | ((darc:A & ed25519:aef) & (darc:D)) | ((darc:B) & (darc:C)) | ((darc:B) & (darc:D)) | ((darc:C) & (darc:D))\"" runBA0 darc show --darc "$ID"

  # with some wrong identities
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'xdarc:A & ed25519:aef' -id darc:B --minimum 2 -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'xdarc:A & ed25519:aef' -id darc:B -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'ed25519:aef &' -id darc:B --minimum 2 -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id 'darc:A & C & ed25519:aef' -id darc:B -replace
  testFail runBA darc rule -rule test:contract --darc "$ID" -sign "$KEY" -id ' ' -id darc:B --minimum 2 -replace
}

testRuleDarc(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -desc testing -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testGrep "Description: \"testing\"" runBA0 darc show -darc $ID
  testOK runBA darc rule -rule spawn:xxx -identity ed25519:abc -darc "$ID" -sign "$KEY"
  testGrep "spawn:xxx - \"ed25519:abc\"" runBA0 darc show -darc "$ID"
  testOK runBA darc rule -replace -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
  testGrep "spawn:xxx - \"ed25519:abc | ed25519:aef\"" runBA0 darc show -darc "$ID"
  testOK runBA darc rule -delete -rule spawn:xxx -darc "$ID" -sign "$KEY"
  testNGrep "spawn:xxx" runBA0 darc show -darc "$ID"

  # re-add the rule to check the restricted mode
  testOK runBA darc rule -rule spawn:xxx -identity ed25519:abc -darc "$ID" -sign "$KEY"
  # removing the unrestricted rule
  testOK runBA darc rule -delete -rule "invoke:darc.evolve_unrestricted" -darc "$ID" -sign "$KEY"
  # now, without using the --restricted flag, it shouldn't be possible to update
  # the darc. Then we try we the --restricted flag.
  testFail runBA darc rule -replace -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
  testOK runBA darc rule --restricted -replace -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
  # same for deleting
  testFail runBA darc rule -delete -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
  testOK runBA darc rule --restricted -delete -rule spawn:xxx -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"

  # test the particular case of the _sign action
  testOK runBA darc rule --restricted -replace -rule _sign -identity "ed25519:abc | ed25519:aef" -darc "$ID" -sign "$KEY"
}

testAddDarcFromOtherOne(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_key ./key.txt -out_id ./id.txt -unrestricted
  KEY=`cat ./key.txt`
  ID=`cat ./id.txt`
  testOK runBA darc rule -rule spawn:darc -identity "$KEY" -darc "$ID" -sign "$KEY"
  testOK runBA darc add -darc "$ID" -sign "$KEY"
}

testAddDarcWithOwner(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA key -save ./key.txt
  KEY=`cat ./key.txt`
  testOK runBA darc add -id "$KEY" -out_id "darc_id.txt"
  ID=`cat ./darc_id.txt`
  testGrep "$KEY" runBA0 darc show -darc "$ID"
}

testExpression(){
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA key -save ./key.txt
  KEY2=`cat ./key.txt`

  testOK runBA darc rule -rule spawn:darc -identity "$KEY | $KEY2" -darc "$ID" -sign "$KEY"
  testOK runBA darc show -darc "$ID"
  testOK runBA darc add -darc "$ID" -sign "$KEY"
  testOK runBA darc add -darc "$ID" -sign "$KEY2"

  testOK runBA darc rule -replace -rule spawn:darc -identity "$KEY & $KEY2" -darc "$ID" -sign "$KEY"
  testFail runBA darc add -darc "$ID" -sign "$KEY"
  testFail runBA darc add -darc "$ID" -sign "$KEY2"
}

runBA(){
  dbgRun ./bcadmin -c config/ --debug $DBG_BCADMIN "$@"
}

runBA0(){
  ./bcadmin -c config/ --debug 0 "$@"
}

testQR() {
  runCoBG 1 2 3
  runGrepSed "export BC=" "" ./"$APP" create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK ./"$APP" qr -admin
}

testUpdateDarcDesc() {
  # We update the description of the latest darc, then we get the latest darc
  # and check if the description changed.
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA darc cdesc --desc "New description"
  testGrep "New description" runBA0 darc show

  # Same test, but with a restricted darc
  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -desc testing
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA darc cdesc --desc "New description" --darc "$ID" --sign "$KEY"
  testGrep "New description" runBA0 darc show --darc "$ID"
}

# Rely on:
# - bcadmin contract name spawn
# - bcadmin contract value spawn
# - bcadmin contract name add
testResolveiid() {
  # We are spawning a value instance, saving its name and see if we can retrieve
  # it and get back the value stored within the value instance.
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA0 contract name spawn 

  # Add the rules
  testOK runBA darc add -out_id ./darc_id.txt -out_key ./darc_key.txt -unrestricted
  ID=`cat ./darc_id.txt`
  KEY=`cat ./darc_key.txt`
  testOK runBA darc rule -rule "spawn:value" --identity "$KEY" --darc "$ID" --sign "$KEY"
  testOK runBA darc rule -rule "_name:value" --identity "$KEY" --darc "$ID" --sign "$KEY"

  # Spawn the value instance
  OUTRES=`runBA0 contract value spawn --value "Hello world" --darc "$ID" --sign "$KEY"`
  VALUE_INSTANCE_ID=$( echo "$OUTRES" | grep -A 1 "instance id" | sed -n 2p )
  matchOK "$VALUE_INSTANCE_ID" ^[0-9a-f]{64}$

  # Save the name with the name contract
  testOK runBA0 contract name invoke add -i $VALUE_INSTANCE_ID -name "myValue" --sign "$KEY"

  # Let's get a wrong name, it should fail
  testFail runBA0 resolveiid --name "do not exist"
  # Let's get it right now
  OUTRES=`runBA0 resolveiid --name "myValue" --namingDarc "$ID"`
  matchOK "$OUTRES" "Here is the resolved instance id:
$VALUE_INSTANCE_ID"

  # Let's try with a wrong darc (the default one), it should fail
  testFail runBA0 resolveiid --name "myValue"

  # Let's get the content of the value contract
  OUTRES=`runBA0 contract value get --instid "$VALUE_INSTANCE_ID"`
  testGrep "Hello world" echo "$OUTRES"
}

# In this test we simply get the config instance
testInstructionGet() {
  runCoBG 1 2 3
  runGrepSed "export BC=" "" runBA create --roster public.toml --interval .5s
  eval $SED
  [ -z "$BC" ] && exit 1

  testOK runBA0 instance get -i 0000000000000000000000000000000000000000000000000000000000000000
  testOK runBA0 instance get -i 0000000000000000000000000000000000000000000000000000000000000000 --hex
}

main

