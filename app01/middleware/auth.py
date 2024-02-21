from urllib import request

from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import HttpResponse, redirect


class AuthMiddleware(MiddlewareMixin):
    """ 中间件1 """
    def process_request(self, request):
        # 排除不需要登录就可以访问的页面
        if request.path_info in ['/login/', "/image/code/"]:
            return
        # 读取当前访问的用户的session信息，如果能读到，说明已登录过，就可以继续向后走
        info_dict = request.session.get("info")
        if info_dict:
            return
        else:
            return redirect("/login/")
        # 如果方法中没有返回值(返回none)，继续向后走
        # 如果有返回值 HttpResponse, render,
        # print("M1.进来了")
        # return HttpResponse("无权访问")

