from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import pandas as pd 
from sklearn.preprocessing import StandardScaler, LabelEncoder

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/predict', methods=['GET', 'POST'])
def user_predict():
    label_encoders_loaded = joblib.load('label_encoders.pkl')
    scaler_loaded = joblib.load('scaler.pkl')
    model_loaded = joblib.load('one_class_svm_model.pkl')

    user_data = request.json
    
    if not user_data:
        return jsonify({'error': 'No data received'}), 400
    
    input_features = [
        user_data['feature1'],
        user_data['feature2'], 
        user_data['feature3'],
        user_data['feature4'],
        user_data['feature5'],
        user_data['feature6'],
        user_data['feature7'],
        user_data['feature8'],
        user_data['feature9'],
        user_data['feature10'],
        user_data['feature11'],
        user_data['feature12'],
        user_data['feature13'],
        user_data['feature14'],
        user_data['feature15'],
        user_data['feature16'],
        user_data['feature17'],
        user_data['feature18'],
        user_data['feature19'],
        user_data['feature20'],
        user_data['feature21'],
        user_data['feature22'],
        user_data['feature23'],
        user_data['feature24'],
        user_data['feature25'],
        user_data['feature26'],
        user_data['feature27'],
        user_data['feature28'],
        user_data['feature29'],
        user_data['feature30'],
        user_data['feature31'],
        user_data['feature32'],
        user_data['feature33'],
        user_data['feature34'],
        user_data['feature35'],
        user_data['feature36'],
        user_data['feature37'],
        user_data['feature38'],
        user_data['feature39'],
        user_data['feature40'],
        user_data['feature41']
    ]

    user_df = pd.DataFrame([input_features])

    user_scaled = scaler_loaded.transform(user_df)

    prediction = model_loaded.predict(user_scaled)
    prediction = 0 if prediction == 1 else 1

    return jsonify({'prediction': prediction})

if __name__ == '__main__':
    app.run(debug=True)    
