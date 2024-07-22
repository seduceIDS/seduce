"""All the inference pipeline."""
import pickle
import onnxruntime as rt
import fasttext
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report

def get_embedding_vector(text, model):
    """Get emb vector."""
    embeddings = [model[word] for word in text.split() if word in model.words]
    if embeddings:
        return np.mean(embeddings, axis=0)
    else:
        # Handle the case when no embeddings are available (e.g., return a zero vector)
        return np.zeros(model.get_dimension())


def get_embedded_list(X, model):
    X_embeddings = []
    for text in X:
        embeddings = [model[word] for word in text.split() if word in model.words]
        if embeddings:
            X_embeddings.append(np.mean(embeddings, axis=0))
        else:
            # Handle the case when no embeddings are available (e.g., skip the text or use a default embedding)
            # For simplicity, we're using a zero vector in this example
            X_embeddings.append(np.zeros(model.get_dimension()))
    # Convert the list of feature vectors to a numpy array
    X_embeddings = np.array(X_embeddings)
    return X_embeddings


def filter_preds(X_data: pd.DataFrame, y_pred: pd.DataFrame, category: int = 1):
    """Filter X data to keep only the rows with the given category."""
    # Check if category is present in y_pred
    y_pred = y_pred.tolist()
    list_idx = [index for index, value in enumerate(y_pred) if value == category]
    return X_data[X_data.index.isin(list_idx)], list_idx


def combine_preds(X, y_preds_1, idxs_1, y_preds_0, idxs_0):
    """Combine both malicious and other preds."""
    final_preds = []
    for i in range(len(X)):
        if i in idxs_1:
            index = idxs_1.index(i)
            final_preds.append(y_preds_1[index])
        elif i in idxs_0:
            index = idxs_0.index(i)
            final_preds.append(y_preds_0[index])
    return final_preds


class InferencePipe:
    def __init__(self, fasttext_1, fasttext_2, svm_1, svm_2):
        """Load models."""
        try:
            self.fasttext_1 = fasttext.load_model(fasttext_1)
            self.fasttext_2 = fasttext.load_model(fasttext_2)
        except Exception as e:
            print("Fasttext Models not loaded!")
            raise e
        try:
            self.svm_1 = rt.InferenceSession(svm_1, providers=["CPUExecutionProvider"])
            self.svm_2 = rt.InferenceSession(svm_2, providers=["CPUExecutionProvider"])
        except Exception as e:
            print("SVM Models not loaded!")
            raise e

        self.data = None
        self.y = None

    def set_data(self, data_path):
        try:
            self.data = pd.read_csv(data_path)
            self.X = self.data['payload']
            self.y = self.data['y']
        except Exception as e:
            print("Data couldnt be read!")

    @staticmethod
    def embed_data(X_data, ft_model):
        """Embed the data with the given fast text model."""
        embd_lst = get_embedded_list(X_data, ft_model)
        return embd_lst

    def run_pipeline(self):
        """Runs the whole pipeline."""
        # First part - inference using ft1 and svm1 model
        fasttext_data_1 = self.embed_data(self.X, self.fasttext_1)

        inputs_1 = self.svm_1.get_inputs()[0].name
        label_name_1 = self.svm_1.get_outputs()[0].name
        y_pred_1 = self.svm_1.run([label_name_1], {inputs_1: fasttext_data_1.astype(np.float32)})[0]

        # We want to split the data to 0 and 1s based on the predicitons
        X_1, idxs_1 = filter_preds(self.X, y_pred_1, category=1)
        X_0, idxs_0 = filter_preds(self.X, y_pred_1, category=0)

        # Second part - inference using ft2 and svm2
        fasttext_data_2 = self.embed_data(X_1, self.fasttext_2)

        inputs_2 = self.svm_2.get_inputs()[0].name
        label_name_2 = self.svm_2.get_outputs()[0].name
        y_pred_2 = self.svm_2.run([label_name_2], {inputs_2: fasttext_data_2.astype(np.float32)})[0]

        y_pred_2_mod = [pred + 1 for pred in y_pred_2]

        final_preds = combine_preds(self.X, y_pred_1, idxs_0, y_pred_2_mod, idxs_1)
        print(classification_report(self.y, final_preds))

    def predict_string(self, input_string):
        """Predict the class for a single input string."""
        # Embed the input string using the first fastText model
        embedded_string_1 = get_embedding_vector(input_string, self.fasttext_1).reshape(1, -1)

        # First prediction using the first SVM model
        inputs_1 = self.svm_1.get_inputs()[0].name
        label_name_1 = self.svm_1.get_outputs()[0].name
        y_pred_1 = self.svm_1.run([label_name_1], {inputs_1: embedded_string_1.astype(np.float32)})[0]

        if y_pred_1[0] == 1:
            # If the first model predicts class 1, embed the string using the second fastText model
            embedded_string_2 = get_embedding_vector(input_string, self.fasttext_2).reshape(1, -1)

            # Second prediction using the second SVM model
            inputs_2 = self.svm_2.get_inputs()[0].name
            label_name_2 = self.svm_2.get_outputs()[0].name
            y_pred_2 = self.svm_2.run([label_name_2], {inputs_2: embedded_string_2.astype(np.float32)})[0]

            # Adjust the prediction for the second model
            return y_pred_2[0] + 1
        else:
            return y_pred_1[0]
