from django.apps import AppConfig
from pathlib import Path
import pickle
import os

class WebappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'account'

    MODEL_PATH = Path("account/models")
    model_pikl_file = MODEL_PATH / "model.pkl"
    #opening pickle file from ./model/model.pkl 
    with open(model_pikl_file, 'rb') as file:  
        model = pickle.load(file)
    predictor = model  