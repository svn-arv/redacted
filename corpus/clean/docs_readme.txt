DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/myapp
connection: mysql://user:pass@db.example.com:3306/app
mongodb://admin:<password>@cluster.example.com/db
password: <%= ENV["DB_PASSWORD"] %>
password: {{ db_password }}
