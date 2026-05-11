import pickle
from features import extract_features

# Load trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Take input from user
url = input("Enter URL: ")

# Extract features
features = extract_features(url)

# Predict
result = model.predict([features])[0]

# Output result
if result == 1:
    print("Phishing ⚠️")
else:
    print("Safe ✅")