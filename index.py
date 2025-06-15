import mysql.connector
from mysql.connector import Error

# Replace these values with your own

try:
    # Attempting to connect to MySQL server
    db = mysql.connector.connect(
        host="ec2-35-174-174-149.compute-1.amazonaws.com",
        user="admin",
        passwd="fypcp4821Aa@#",
        port=3306
    )
    if db.is_connected():
        print("Connected to MySQL Server successfully")

    mycursor = db.cursor()
    mycursor.execute("SHOW DATABASES")

    for db_name in mycursor:
        print(db_name)

except Error as e:
    print("Error:", e)

finally:
    if 'db' in locals() and db.is_connected():
        db.close()
        print("MySQL connection closed")