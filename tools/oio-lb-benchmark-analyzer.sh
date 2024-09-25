#!/bin/bash

# This tool is used to launch and analyze output of oio-lb-benchmark.
# It takes as input a file containing capture score services (oio-lb-capture output),
# extracts all the pools policy and run oio-lb-benchmark for each pool policy.
# Next it will extract interesting data from the oio-lb-benchmark output 
# and it will generate graphs showing, given the pool policy used,
# the number of times rawx services have been selected.
# Get option
while getopts ":eh" opt; do
  case $opt in
    e)
      # Create virtual environment option
      VENV_NAME="analyzer-env"
      ;;
    h)
      # Help option
      echo "Usage: $0 [-e] <services_score>"
      echo ""
      echo "  -e  Create or activate dedicated python virtual environment: analyzer-env."
      echo "      If analyze-env has been previously created, it will be activated"
      echo "      without creating a new one."
      echo ""
      echo "  <services_score>  file with oio-lb-capture output (required)"
      exit 0
      ;;
    \?)
      echo "Error: Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Check if virtual environment is enabled
if [ -n "$VENV_NAME" ]; then
    # Check if virtualenv is installed
    if ! command -v virtualenv &> /dev/null
    then
        echo "Error: virtualenv not found. Please install it first."
        exit 1
    fi
    # Create the virtual environment
    if [ ! -d $VENV_NAME ]; then
        echo "Creating virtual environment '$VENV_NAME'..."
        virtualenv -p python3 $VENV_NAME
    fi

    # Activate the virtual environment
    echo "Activating virtual environment '$VENV_NAME'..."
    source $VENV_NAME/bin/activate
fi

# Shift the arguments to the left to remove the parsed options
shift $((OPTIND-1))

# Check if oio services scores capture is provided as an argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 [options] services_score"
  echo "Run with -h to get more information"
  exit 1
fi

# Check if a dedicated virtual env is being used
if [ -z "${VIRTUAL_ENV}" ]; then
	echo "Please activate a python virtual env to enable dependencies installation in a dedicated virtual env."
  echo "Or add option -e to create a new dedicated python virtual env"
	exit 1
fi

echo "*******************************************************************"
echo Check dependencies
echo "*******************************************************************"
# Check if dependencies are installed
pip install matplotlib pandas plotly > /dev/null 2>&1

if ! command -v sponge >/dev/null 2>&1
then
    # moreutils is not installed
    echo "moreutils is not installed. Please install it as follows:"
    echo "sudo apt-get update"
    echo "sudo apt-get install -y moreutils"
	exit 1
else
    echo "moreutils is already installed."
fi

INPUT_FILE=$1
FOLDER=$(dirname "$INPUT_FILE")
FILE_NAME=$(basename "$INPUT_FILE")
FILE_NAME_NO_EXT="${FILE_NAME%%.*}"
RESULT_FOLDER="${FOLDER}/${FILE_NAME_NO_EXT}_RESULT"
# Create result folder
mkdir -p "$RESULT_FOLDER"
SERVICE_TYPE="rawx"

echo "*******************************************************************"
echo Extract all pools policy to use with benchmark tool
echo "*******************************************************************"


POOLS_POLICY=$(grep "#.*" $INPUT_FILE | head -n -1 | tail -n +3 | grep $SERVICE_TYPE | awk -F: '{print $2}')

echo $POOLS_POLICY

echo "*******************************************************************"
echo Execute benchmark tool for each pool policy
echo "*******************************************************************"

OUTPUT_FILES=()
for pool in $POOLS_POLICY; do 
	OUTPUT_FILE="${RESULT_FOLDER}/${FILE_NAME_NO_EXT}_${pool}_output.txt"
	CLEANED_OUTPUT_FILE="${RESULT_FOLDER}/${FILE_NAME_NO_EXT}_${pool}"
	OUTPUT_FILES+=($CLEANED_OUTPUT_FILE)
	CLEANED_OUTPUT_FILE="${CLEANED_OUTPUT_FILE}.txt"
	oio-lb-benchmark $INPUT_FILE $pool >> $OUTPUT_FILE 2>&1
  # Keep only data to plot
	echo clean the benchmark output in $OUTPUT_FILE
	head -n -3 $OUTPUT_FILE | tail -n +2 | awk '{print $8 " " $10}' | sort | sponge $CLEANED_OUTPUT_FILE;
done

echo "*******************************************************************"
echo Populate a map with score of each service
echo "*******************************************************************"

SCORES=$(head -n -1 $INPUT_FILE | grep -v "#.*" | awk '{print $1 ":" $3}')
# echo $SCORES

declare -A my_map

for score in $SCORES; do
	key=$(echo "$score" | awk -F: '{print $1}')
	value=$(echo "$score" | awk -F: '{print $2}')
	my_map[$key]=$value;
done
# echo Print the map
# echo ${my_map[@]}

echo "*******************************************************************"
echo List output files
echo "*******************************************************************"
echo "${OUTPUT_FILES[@]}"

echo "*******************************************************************"
echo Add score to each rawx in output file
echo "*******************************************************************"
OUTPUT_FILES_WITH_SCORE=()
for output_file in "${OUTPUT_FILES[@]}"; do
	NEW_OUTPUT_FILE="${output_file}_with_score.txt"
	OUTPUT_FILES_WITH_SCORE+=($NEW_OUTPUT_FILE)
	echo Add score in $NEW_OUTPUT_FILE
	# Loop on each line of the file
	while IFS= read -r line
	do
	    # Add corresponding rawx service score to each line
	    rawx=$(echo "$line" | awk '{print $1}')
	    echo "$line ${my_map[$rawx]}" >> "$NEW_OUTPUT_FILE";
	done < "${output_file}.txt"
done

echo "*******************************************************************"
echo List output files with scores
echo "*******************************************************************"

echo "${OUTPUT_FILES_WITH_SCORE[@]}"

echo "*******************************************************************"
echo Generate graphs
echo "*******************************************************************"

for file in "${OUTPUT_FILES_WITH_SCORE[@]}"; do
	base_name=$(basename "$file" .txt)
	python - <<END
import pandas as pd
import plotly.graph_objects as go

# Read data to plot
file_path = "$file"
data = pd.read_csv(file_path, sep=' ', header=None, names=['Rawx_id', 'Nb_selection', 'Score'])

# Create interactive graphs
fig = go.Figure(data=[go.Scatter3d(
    x=data['Rawx_id'],         # Axe X : Rawx id
    y=data['Nb_selection'],    # Axe Y : number of times the rawx has been selected
    z=data['Score'],           # Axe Z : the score of the rawx at time of selection
    mode='markers',
    marker=dict(
        size=5,
        color=data['Score'],   # Colored according to the score column
        colorscale='Viridis',  # Colors
        opacity=0.8
    )
)])

# Add axes titles
fig.update_layout(scene = dict(
                    xaxis_title='Rawx_id (X)',
                    yaxis_title='Nb_selection (Y)',
                    zaxis_title='Score (Z)'),
                  title="${base_name}")

# Save the graph as html file
graph = "${RESULT_FOLDER}/${base_name}.html"
fig.write_html(graph)
END
	echo "Generate graph for $file and save it as ${base_name}.html"
done
