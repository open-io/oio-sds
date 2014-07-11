
ns="TESTNS"
hn=`hostname`

dataMeta1="/DATA/$ns/$hn/meta1-1"
dataMeta2="/DATA/$ns/$hn/meta2-1"





tt=~/build/crawler/test_crawler


echo "=== trip_container ==="
sudo $tt -b trip_container -a "-trip_container.s=$dataMeta2"

echo "=== trip_content ==="
sudo $tt -b trip_content -a "-trip_content.s=$dataMeta2"

echo "=== trip_prefix ==="
sudo $tt -b trip_prefix -a "-trip_prefix.s=$dataMeta1"

echo "=== trip_chunk ==="
sudo $tt -b trip_chunk -a "-trip_chunk.s=$dataMeta2"

echo "=== crawler ==="
sudo $tt -b crawler -a "-Oaction=action_purge_container -trip=trip_container -- -trip_container.s=$dataMeta2 -action_purge_container.n=$ns"

echo "=== action_purge ==="
sudo $tt -b action_purge_container_service -a "-Oaction=action_purge_container -trip=trip_container -- -trip_container.s=$dataMeta2 -action_purge_container.n=$ns"



