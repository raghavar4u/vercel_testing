# Use the official Python slim image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy only necessary files
COPY app\ 1.py /app/app.py

# Install minimal dependencies
RUN pip install --no-cache-dir streamlit==1.40.2 pandas numpy

# Expose the Streamlit port
EXPOSE 7860

# Run the Streamlit app
CMD ["streamlit", "run", "app.py", "--server.port=7860", "--server.enableCORS=false"]