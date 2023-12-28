# 使用一个基础的 Python 镜像作为基础
FROM python:3.8

# 设置环境变量，可以根据需要进行修改
#ENV PYTHONDONTWRITEBYTECODE 1
#ENV PYTHONUNBUFFERED 1

#安装mysqlclient系统依赖库
RUN apt-get update && apt-get install -y libmariadb-dev

# 创建工作目录并设置为工作目录
WORKDIR /app

# 复制项目代码到容器中的工作目录
COPY . /app/

# 安装项目依赖项，可以根据你的项目使用 pip 或 pipenv
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 运行 Django 应用程序，可以根据需要修改
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
