import streamlit as st
import sqlite3
import pandas as pd
import hashlib
from streamlit_cookies_manager import EncryptedCookieManager

cookies = EncryptedCookieManager(prefix="myapp", password="adminapp123")

if not cookies.ready():
    st.stop()

# Hash password for security
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_tables():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email TEXT UNIQUE,
                    role TEXT)''')
    # Create admin table
    c.execute('''CREATE TABLE IF NOT EXISTS admin (
                    username TEXT UNIQUE,
                    password TEXT)''')
    conn.commit()
    conn.close()

def login_user(username):
    cookies['logged_in'] = 'True'
    cookies['username'] = username
    cookies.save()

def logout_user():
    cookies['logged_in'] = ''
    cookies['username'] = ''
    cookies.save()


def add_user(name, email, role):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (name, email, role) VALUES (?, ?, ?)', (name, email, role))
    conn.commit()
    conn.close()

def view_all_users(limit, offset):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users LIMIT ? OFFSET ?', (limit, offset))
    data = c.fetchall()
    conn.close()
    return data

def search_user_by_name_or_email(search_term):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE name LIKE ? OR email LIKE ?', ('%' + search_term + '%', '%' + search_term + '%'))
    data = c.fetchall()
    conn.close()
    return data

def update_user_by_email(old_email, new_name, new_email, new_role):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, email = ?, role = ? WHERE email = ?", 
              (new_name, new_email, new_role, old_email))
    conn.commit()
    conn.close()

def delete_user_by_email(email):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE email=?', (email,))
    conn.commit()
    conn.close()

def get_user_count():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    count = c.fetchone()[0]
    conn.close()
    return count

def create_super_admin(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    
    # Check if the username already exists
    c.execute('SELECT COUNT(*) FROM admin WHERE username = ?', (username,))
    count = c.fetchone()[0]
    
    if count == 0:
        hashed_password = hash_password(password)
        c.execute('INSERT INTO admin (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        st.success("Admin created successfully!")
    
    conn.close()

def authenticate(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute('SELECT * FROM admin WHERE username=? AND password=?', (username, hashed_password))
    result = c.fetchone()
    conn.close()
    return bool(result)

def get_admin():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM admin LIMIT 1')
    admin = c.fetchone()
    conn.close()
    return admin

def main():
    if  cookies['logged_in'] == 'True':
        st.title("Super Admin - User Management")
    else:
        st.title("Log in")

    if 'page' not in st.session_state:
        if cookies['logged_in'] == 'True':
           st.session_state['page'] = "view_users"
        else:
           st.session_state['page'] = "login"

    if 'page_number' not in st.session_state:
        st.session_state['page_number'] = 1

    create_tables()
    admin = get_admin()
    if not admin :
        create_super_admin('admin', 'admin')

    if not cookies['logged_in'] == 'True' and st.session_state['page'] == "login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate(username, password):
                login_user(username)
                st.session_state['page'] = "view_users"
                st.rerun()
            else:
                st.error("Invalid credentials")
        return

    if cookies['logged_in'] == 'True':
        st.sidebar.header("Menu")
        if st.sidebar.button("Dashboard"):
            st.session_state['page'] = "view_users"

        if st.sidebar.button("Logout"):
            logout_user()
            st.session_state['page'] = "login"
            st.rerun() 
         

    if st.session_state['page'] == "add_user":
        st.subheader("Add New User")
        name = st.text_input("Name")
        email = st.text_input("Email")
        role = st.selectbox("Role", ["Admin", "User", "Viewer"])
        if st.button("Add User", key="add_user_button"):
            try:
                add_user(name, email, role)
                st.success(f"User {name} added successfully")
                st.session_state['page'] = "view_users" 
                st.rerun()  
            except sqlite3.IntegrityError:
                st.error(f"User with email {email} already exists.")
    if st.session_state['page'] == "view_users" and  cookies['logged_in'] == 'True':
       
        col1, col2 = st.columns([4, 1]) 

        with col1:
            st.subheader("All Users")

        with col2:
            if st.button("Add User", key="add users"):
                st.session_state['page'] = "add_user"
                st.rerun()

        search_term = st.text_input("Search",placeholder="Search by Name or Email", label_visibility="collapsed")
        per_page = 5
        user_count = get_user_count()
        max_pages = (user_count // per_page) + 1

        if st.session_state['page_number'] > max_pages:
            st.session_state['page_number'] = max_pages

        offset = (st.session_state['page_number'] - 1) * per_page

        # If there's a search term, search for users
        if search_term:
            users = search_user_by_name_or_email(search_term)
        else:
            users = view_all_users(limit=per_page, offset=offset)

        if users:
            df = pd.DataFrame(users, columns=["ID", "Name", "Email", "Role"])

            # Display table headers manually
            col1, col2, col3, col4, col5, col6 = st.columns([2, 3, 5, 2, 2, 2])
            col1.write("ID")
            col2.write("Name")
            col3.write("Email")
            col4.write("Role")
            col5.write("Edit")
            col6.write("Delete")

            for index, row in df.iterrows():
                col1, col2, col3, col4, col5, col6 = st.columns([2, 3, 6, 2, 2, 2])
                col1.write(row['ID'])
                col2.write(row['Name'])
                col3.write(row['Email'])
                col4.write(row['Role'])

                # Unique keys for buttons based on row index
                if col5.button("Edit", key=f"edit_{row['Email']}_{index}"):
                    st.session_state['edit_email'] = row['Email']
                    st.session_state['page'] = "edit_user"
                    st.rerun()

                if col6.button("Delete", key=f"delete_{row['Email']}_{index}"):
                    delete_user_by_email(row['Email'])
                    st.success(f"User {row['Email']} deleted successfully")
                    st.rerun()

           
            total_users = get_user_count()
            max_pages = (total_users - 1) // per_page + 1

            if max_pages > 1:
                col1, col2, col3 = st.columns([1, 2, 1])
                if st.session_state['page_number'] > 1:
                    if col1.button("Previous"):
                        st.session_state['page_number'] -= 1
                        st.rerun()
                if st.session_state['page_number'] < max_pages:
                    if col3.button("Next"):
                        st.session_state['page_number'] += 1
                        st.rerun()

        else:
            st.write("No users found.")

    
    if 'edit_email' in st.session_state and st.session_state['page'] == "edit_user":
        edit_user_email = st.session_state['edit_email']
        search_result = search_user_by_name_or_email(edit_user_email)

        if len(search_result) == 0:
            st.error(f"No user found with email: {edit_user_email}")
            del st.session_state['edit_email']
            st.rerun()
        else:
            user_to_edit = search_result[0]
            st.subheader(f"Edit User: {edit_user_email}")
            new_name = st.text_input("New Name", user_to_edit[1])
            new_email = st.text_input("New Email", user_to_edit[2])
            new_role = st.selectbox("New Role", ["Admin", "User", "Viewer"], 
                                    index=["Admin", "User", "Viewer"].index(user_to_edit[3]))

            # Update user information
            if st.button("Update User"):
                if new_email != user_to_edit[2] and len(search_user_by_name_or_email(new_email)) > 0:
                    st.error(f"Email {new_email} is already in use. Please use a different email.")
                else:
                    update_user_by_email(edit_user_email, new_name, new_email, new_role)
                    st.success(f"User {edit_user_email} updated successfully")
                    del st.session_state['edit_email']
                    st.session_state['page'] = 'view_users'
                    st.rerun()

        
            if st.button("Cancel"):
                del st.session_state['edit_email']
                st.session_state['page'] = 'view_users'
                st.rerun()

if __name__ == "__main__":

    main()
    
