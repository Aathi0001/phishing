import streamlit as st
import pickle
import numpy as np
import pandas as pd
import mysql.connector
import smtplib
from email.message import EmailMessage
import requests
from utils import unmask
from sklearn.feature_extraction.text import TfidfVectorizer
import plotly.graph_objects as go

import plotly.express as px
st.set_page_config(page_title="Phishing URL Detector", layout="wide")
# The rest of your Streamlit app code goes here
#st.title("My Streamlit App")
#st.write("This is a Streamlit app with a background image.")


email_config = st.secrets["email"]



def send_feedback_email(comment):
    try:
        msg = EmailMessage()
        msg.set_content(f"New Feedback Received:\n\n{comment}")
        msg["Subject"] = "New Feedback from URL Inspector"
        msg["From"] = email_config["sender"]
        msg["To"] = email_config["receiver"]

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email_config["sender"], email_config["password"])
        server.send_message(msg)
        server.quit()
    except Exception as e:
        st.error(f"Email error: {e}")


# Load the trained model
with open('./models/vect.pkl', 'rb') as f:
    tfidf_vectorizer = pickle.load(f)
with open('./models/lr.pkl', 'rb') as f:
    lr = pickle.load(f)    
with open('./models/sv.pkl', 'rb') as f:
    sv = pickle.load(f)
with open('./models/dt.pkl', 'rb') as f:
    dt = pickle.load(f)    
with open('./models/dtr.pkl', 'rb') as f:
    dtr = pickle.load(f)
with open('./models/rf.pkl', 'rb') as f:
    rf = pickle.load(f)    
with open('./models/r.pkl', 'rb') as f:
    r = pickle.load(f)    
with open('./models/x.pkl', 'rb') as f:
    x = pickle.load(f)    
with open('./models/xr.pkl', 'rb') as f:
    xr = pickle.load(f)
with open('./models/xm.pkl', 'rb') as f:
    xm = pickle.load(f)    
with open('./models/grbm.pkl', 'rb') as f:
    grbm = pickle.load(f)   
with open('./models/ensemble_model.pkl', 'rb') as f:
    ensemble_model = pickle.load(f)
    
def predict_with_details(text_input):
    url = unmask(text_input)
    if url == 'not a valid url' or url is None:
        return "Invalid URL", {}
    
    preprocessed_input = pd.DataFrame(tfidf_vectorizer.transform([url]).toarray(), columns=tfidf_vectorizer.get_feature_names_out())

    results = {
        'Logistic Regression': int(lr.predict(preprocessed_input)[0]),
        'SVM': int(sv.predict(preprocessed_input)[0]),
        'Decision Tree': int(dt.predict(preprocessed_input)[0]),
        'Random Forest': int(rf.predict(preprocessed_input)[0]),
        'Ridge Classifier': int(r.predict(preprocessed_input)[0]),
        'XGBoost': int(x.predict(preprocessed_input)[0]),
        'XGBoost Regressor': int(xr.predict(preprocessed_input)[0]),
        'XGBoost Multi': int(xm.predict(preprocessed_input)[0]),
        'GRBM': int(grbm.predict(preprocessed_input)[0]),
        'Decision Tree Regressor': int(dtr.predict(preprocessed_input)[0]),
    }

    ensemble_input = np.column_stack(list(results.values()))
    ensemble_pred = int(ensemble_model.predict(ensemble_input)[0])
    prediction = "Phishing URL" if ensemble_pred == 1 else "Normal URL"

    return prediction, results

def display_result(url, prediction, model_scores):
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown(f"**URL:** `{url}`")
        if prediction == "Invalid URL":
            st.markdown("**Result:** ⚠️ Invalid URL or Suspicious URL")
        else:
            st.markdown(f"**Result:** {'🟥 Phishing' if prediction == 'Phishing URL' else '🟩 Safe'}")

    with col2:
        st.markdown("**Model Votes:**")
        if model_scores:
            df = pd.DataFrame(model_scores.items(), columns=["Model", "Prediction"])
            df["Prediction"] = df["Prediction"].replace({0: "Safe", 1: "Phishing"})
            df.insert(0, 'Index', df.index + 1)
            st.dataframe(df)
        else:
            st.info("Model votes not available (invalid or unreachable URL).")

            # Add a graph for visual representation
    if model_scores:
        st.markdown("**Model Voting Bar Chart:**")
        vote_df = pd.DataFrame(list(model_scores.items()), columns=["Model", "Vote"])
        vote_df["Vote Label"] = vote_df["Vote"].replace({0: "Safe", 1: "Phishing"})

        chart_data = vote_df.set_index("Model")[["Vote"]]
        st.bar_chart(chart_data)

        st.markdown(
    """
    <div style='
        background-color: #1e1e1e;
        padding: 15px 20px;
        border-left: 4px solid #4FC3F7;
        border-radius: 6px;
        margin-top: 20px;
        color: #f0f0f0;
        font-size: 15px;
        max-width: 400px;
    '>
        <b>Note:</b><br>
        <span style='color: #FF6F61;'>• Filled bars = Phishing</span><br>
        <span style='color: #81C784;'>• Empty bars = Safe</span>
    </div>
    """,
    unsafe_allow_html=True
)


def apply_dark_mode():
    st.markdown(
        """
        <style>
        /* Global background color */
        body {
            background-color: #1e1e1e;
            color: #f0f0f0;
        }
        .sidebar .sidebar-content {
            background-color: #2c2c2c;
            color: #f0f0f0;
        }
        .css-1lcbj1d {
            background-color: #2c2c2c;
        }
        .stTextInput>div>div>input {
            background-color: #333333;
            color: #f0f0f0;
            border: 1px solid #444444;
        }
        .stButton>button {
            background-color: #444444;
            color: #f0f0f0;
            border: 1px solid #555555;
        }
        /* Hide Streamlit footer and menu button */
        #MainMenu, footer {
            visibility: hidden;
        }
        </style>
        """, unsafe_allow_html=True
    )

# Streamlit app

def main():

    apply_dark_mode()


    
    with st.sidebar:
        st.markdown("<h2 style='text-align: center; color: #ffffff;'>🔍 URL Inspector</h2>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-size: 14px; color: #cccccc;'>Detect whether a URL is <strong>safe</strong> or <strong>phishing</strong>.</p>", unsafe_allow_html=True)
        st.markdown("<hr style='border-color: #444;'>", unsafe_allow_html=True)

        st.info("Enter URLs to scan – separate with commas for multiple checks.")

        # How to Use
        st.markdown("<h4 style='color: #ffffff;'>📘 How to Use</h4>", unsafe_allow_html=True)
        st.markdown("""
            <ul style="font-size: 13px; padding-left: 15px; color: #cccccc;">
                <li>Enter one or more URLs in the main input box.</li>
                <li>Click on the <strong>'Check URLs'</strong> button.</li>
                <li>View predictions and model confidence scores.</li>
            </ul>
        """, unsafe_allow_html=True)

        st.markdown("<hr style='border-color: #444;'>", unsafe_allow_html=True)
        
        # Feedback Section on Main Page
        st.markdown("<h4 style='color: #ffffff;'>💬 Feedback</h4>", unsafe_allow_html=True)
        user_feedback = st.text_area("How can we improve?", placeholder="Enter your feedback here...")

        if st.button("Submit Feedback"):
            if user_feedback.strip():
                # save_feedback_to_db(user_feedback)  # Commented for now
                send_feedback_email(user_feedback)
                st.success("✅ Thank you for your feedback!")
            else:
                st.warning("⚠️ Please enter some feedback before submitting.")

        st.markdown("<hr style='border-color: #444;'>", unsafe_allow_html=True)

        # FAQ
        st.markdown("<h4 style='color: #ffffff;'>❓ FAQ</h4>", unsafe_allow_html=True)
        st.markdown("""
            <p style="font-size: 13px; color: #cccccc;"><strong>Q:</strong> What is a phishing URL?<br>
            <strong>A:</strong> A fraudulent link that tricks users into revealing personal data.</p>

            <p style="font-size: 13px; color: #cccccc;"><strong>Q:</strong> How accurate is the app?<br>
            <strong>A:</strong> It uses several ML models with high accuracy, but caution is always advised.</p>
        """, unsafe_allow_html=True)

    st.title("🛡️ Think Before You Click!")

    st.markdown("### Paste URLs (one or multiple, separated by comma):")
    input_text = st.text_area("Enter URL(s)", height=150, placeholder="https://example.com, https://bit.ly/abc")

    if st.button("Check URLs"):
        urls = [url.strip() for url in input_text.split(",") if url.strip()]
        for i, url in enumerate(urls):
            prediction, details = predict_with_details(url)
            display_result(url, prediction, details)

            # Add visual gap or separator after each result
            if i < len(urls) - 1:
                st.markdown("<hr style='margin: 40px 0;'>", unsafe_allow_html=True)

            

# Run the app
if __name__ == '__main__':
    main()
