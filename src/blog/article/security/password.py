import re

from flask import request

from src.database import get_db_connection


def set_article_password(aid, passwd):
    db = get_db_connection()
    aid = int(aid)
    try:
        with db.cursor() as cursor:
            query = "SELECT * FROM article_content WHERE aid = %s;"
            cursor.execute(query, (aid,))
            result = cursor.fetchone()
            if result:
                query = "UPDATE `article_content` SET `passwd` = %s WHERE `article_content`.`aid` = %s;"
                cursor.execute(query, (passwd, aid,))
            else:
                query = "INSERT INTO `article_content` (`aid`, `passwd`) VALUES (%s, %s);"
                cursor.execute(query, (aid, passwd,))
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        db.commit()
        try:
            cursor.close()
        except NameError:
            pass
        db.close()
        return True

def get_article_password(aid):
    db = get_db_connection()
    try:
        with db.cursor() as cursor:
            query = "SELECT `passwd` FROM article_content WHERE aid = %s"
            cursor.execute(query, (int(aid),))
            result = cursor.fetchone()
            if result:
                return result[0]
    except ValueError as e:
        #app.logger.error(f"Value error: {e}")
        pass
    except Exception as e:
        #app.logger.error(f"Unexpected error: {e}")
        pass
    finally:
        db.close()


def get_apw_form(aid):
    return '''
        <div id="password-modal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full">
            <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                <div class="mt-3 text-center">
                    <h3 class="text-lg leading-6 font-medium text-gray-900">更改文章密码</h3>
                    <div class="mt-2 px-7 py-3">
                        <p class="text-sm text-gray-500 mb-3">
                            请输入新的文章访问密码（至少4位，包含字母和数字）
                        </p>
                        <input type="password" id="new-password" name="new-password"
                               class="w-full px-3 py-2 border border-gray-300 rounded-md" 
                               placeholder="输入新密码">
                    </div>
                    <div class="flex justify-center gap-4 px-4 py-3">
                        <button id="cancel-password" 
                                class="px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300"
                                onclick="document.getElementById('password-modal').remove()">
                            取消
                        </button>
                        <button id="confirm-password" 
                                hx-post="/api/article/password/''' + str(aid) + '''"
                                hx-include="#new-password"
                                hx-target="#password-modal"
                                hx-swap="innerHTML"
                                class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                            确认更改
                        </button>
                    </div>
                </div>
            </div>
        </div>
        '''

def check_apw_form(aid):
    try:
        new_password = request.form.get('new-password')

        # 验证密码格式
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{4,}$', new_password):
            return '''
            <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                <div class="mt-3 text-center">
                    <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                        <svg class="h-6 w-6 text-red-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg leading-6 font-medium text-gray-900">密码格式错误</h3>
                    <div class="mt-2 px-7 py-3">
                        <p class="text-sm text-gray-500">
                            密码需要至少4位且包含字母和数字！
                        </p>
                    </div>
                    <div class="px-4 py-3">
                        <button onclick="document.getElementById('password-modal').remove()"
                                class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                            关闭
                        </button>
                    </div>
                </div>
            </div>
            '''

        # 更新密码
        set_article_password(aid, new_password)

        # 返回成功响应
        return '''
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                <svg class="h-6 w-6 text-green-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
            </div>
            <div class="mt-3 text-center">
                <h3 class="text-lg leading-6 font-medium text-gray-900">密码更新成功</h3>
                <div class="mt-2 px-7 py-3">
                    <p class="text-sm text-gray-500">
                        新密码将在10分钟内生效
                    </p>
                </div>
                <div class="px-4 py-3">
                    <button onclick="document.getElementById('password-modal').remove()"
                            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                        关闭
                    </button>
                </div>
            </div>
        </div>
        '''
    except Exception as e:
        #app.logger.error(f"更新密码失败: {str(e)}")
        return '''
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100">
                <svg class="h-6 w-6 text-red-600" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </div>
            <h3 class="text-lg leading-6 font-medium text-gray-900">操作失败</h3>
            <div class="mt-2 px-7 py-3">
                <p class="text-sm text-gray-500">
                    服务器内部错误，请稍后再试
                </p>
            </div>
            <div class="px-4 py-3">
                <button onclick="document.getElementById('password-modal').remove()"
                        class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                    关闭
                </button>
            </div>
        </div>
        ''', 500

