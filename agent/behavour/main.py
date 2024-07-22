from core.config import *
from pipeline.process_pipe import InferencePipe


def main(input_data):
    """Given input data path it runs the whole inference pipeline."""
    inferer = InferencePipe(fasttext_1=FASTTEXT1, fasttext_2=FASTTEXT2, svm_1=SVM1, svm_2=SVM2)

    return inferer.predict_string(input_data)

