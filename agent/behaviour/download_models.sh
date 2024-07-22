#!/bin/bash
MAX_ANOMALIES="$1"
MAX_ANOMALIES=${MAX_ANOMALIES:-2}  # Default to 2 if not set

# Load the .env file
if [ -f .env ]; then
    source .env
else
    echo ".env file not found!"
    exit 1
fi

# Directory to store the downloaded models
MODEL_DIR="models"

# Check if the directory exists, and delete it if it does
if [ -d "$MODEL_DIR" ]; then
    rm -rf "$MODEL_DIR"
fi

# Create the directory if it doesn't exist
mkdir -p $MODEL_DIR

# Define model URLs and file names based on the max-anomalies parameter
if [ "$MAX_ANOMALIES" == "2" ]; then
    wget -O "$MODEL_DIR/model.bin" "$MAX_ANOMALIES_2_URL_FT1"
    wget -O "$MODEL_DIR/model2.bin" "$MAX_ANOMALIES_2_URL_FT2"
    wget -O "$MODEL_DIR/svm_model.onnx" "$MAX_ANOMALIES_2_URL_SVM1"
    wget -O "$MODEL_DIR/svm_model2.onnx" "$MAX_ANOMALIES_2_URL_SVM2"
elif [ "$MAX_ANOMALIES" == "3" ]; then
    wget -O "$MODEL_DIR/model.bin" "$MAX_ANOMALIES_3_URL_FT1"
    wget -O "$MODEL_DIR/model2.bin" "$MAX_ANOMALIES_3_URL_FT2"
    wget -O "$MODEL_DIR/svm_model.onnx" "$MAX_ANOMALIES_3_URL_SVM1"
    wget -O "$MODEL_DIR/svm_model2.onnx" "$MAX_ANOMALIES_3_URL_SVM2"
else
    echo "Invalid value for MAX_ANOMALIES. Supported values are 2 or 3."
    exit 1
fi

echo "Model download completed."
