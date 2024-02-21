from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect
from app01 import models
from django.utils.safestring import mark_safe
from app01.encrypt import md5
# Create your views here.

def depart_list(request):
    """部门列表"""
    info = request.session.get("info")
    if not info:
        return redirect('/login/')
    # 去数据库中获取所有的部门列表
    # [对象，对象，对象]
    queryset = models.Department.objects.all()

    page_object = Pagination(request, queryset,page_size=2)
    context = {
        "queryset": page_object.page_queryset,
        "page_string": page_object.html(),
    }

    return render(request, "depart_list.html", context)

def depart_add(request):
    """ 添加部门 """
    info = request.session.get("info")
    if not info:
        return redirect('/login/')

    if request.method == "GET":
        return render(request, "depart_add.html")

    # 获取用户通过POST提交过来的数据（title输入为空）
    title = request.POST.get("title")

    # 保存到数据库
    models.Department.objects.create(title=title)

    # 重定向回部门列表
    return redirect("/depart/list/")

def depart_delete(request):
    """ 删除部门 """
    # 获取id
    # /depart/delete/?nid=1
    nid = request.GET.get('nid')
    # 删除
    models.Department.objects.filter(id=nid).delete()
    # 跳转回部门列表
    return redirect("/depart/list/")

def depart_edit(request, nid):
    """ 修改部门 """
    if request.method == "GET":
        # 根据nid，获取他的数据
        row_object = models.Department.objects.filter(id=nid).first()
        return render(request, 'depart_edit.html', {"row_object":row_object})

    # 用户提交的标题拿到
    title = request.POST.get("title")
    # 根据ID找到数据库中的数据并进行更新
    models.Department.objects.filter(id=nid).update(title=title)

    # 重定向回部门列表
    return redirect("/depart/list/")

def user_list(request):
    """ 用户管理 """

    info = request.session.get("info")
    if not info:
        return redirect('/login/')

    # 获取所有用户列表[obj, obj, obj]
    queryset = models.UserInfo.objects.all()

    page_object = Pagination(request, queryset,page_size=10)
    context = {
        "queryset": page_object.page_queryset,
        "page_string":page_object.html(),
    }

    return render(request, "user_list.html", context)

def user_add(request):
    """ 添加用户 """
    info = request.session.get("info")
    if not info:
        return redirect('/login/')

    if request.method == "GET":
        context = {
            'gender_choices': models.UserInfo.gender_choices,
            'depart_list': models.Department.objects.all()
        }
        return render(request, "user_add.html", context)

    # 获取用户提交的数据
    user = request.POST.get("user")
    pwd = request.POST.get("pwd")
    age = request.POST.get("age")
    ac = request.POST.get("ac")
    ctime = request.POST.get("ctime")
    gd = request.POST.get("gd")
    dp = request.POST.get("dp")

    # 添加到数据库中
    models.UserInfo.objects.create(name=user, password=pwd, age=age, account=ac, create_time=ctime, gender=gd, depart_id=dp)

    # 返回到用户列表页面
    return redirect("/user/list/")

from django import forms
class UserModelForm(forms.ModelForm):
    name = forms.CharField(min_length=3, label="用户名")
    class Meta:
        model = models.UserInfo
        fields = ["name", "password", "age", "account", "create_time", "gender", "depart"]
        # widgets = {
        #     "name": forms.TextInput(attrs={"class": "form-control"}),
        #     "password": forms.PasswordInput(attrs={"class": "form-control"}),
        #     "age": forms.TextInput(attrs={"class": "form-control"}),
        #     "password": forms.PasswordInput(attrs={"class": "form-control"}),
        # }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

def user_model_form_add(request):
    """ 添加用户（基于modelform） """
    if request.method == "GET":
        form = UserModelForm()
        return render(request, "user_model_form_add.html",{"form":form})

    # 用户POST提交数据，数据校验
    form = UserModelForm(data=request.POST)
    if form.is_valid():
        # print(form.cleaned_data)
        # 如果数据合法，保存到数据库
        # models.UserInfo.objects.create()
        form.save()
        return redirect("/user/list/")

    # 校验失败（在页面上显示错误信息）
    return render(request, "user_model_form_add.html",{"form":form})

def user_edit(request, nid):
    """ 编辑用户 """

    info = request.session.get("info")
    if not info:
        return redirect('/login/')

    row_oject = models.UserInfo.objects.filter(id=nid).first()
    if request.method == "GET":
        # 根据ID去数据库获取要编辑的那一行数据
        form = UserModelForm(instance=row_oject)
        return render(request, 'user_edit.html',{"form": form})

    form = UserModelForm(data=request.POST, instance=row_oject)
    if form.is_valid():
        form.save()
        return redirect("/user/list/")

    return render(request, 'user_edit.html',{"form": form})

def user_delete(request, nid):
    models.UserInfo.objects.filter(id=nid).delete()
    return redirect("/user/list/")

from app01.utils.pagination import Pagination
def pretty_list(request):
    """ 靓号列表 """

    data_dict = {}
    search_data = request.GET.get("q", "")
    if search_data:
        data_dict["mobile__contains"] = search_data

    queryset = models.PrettyNum.objects.filter(**data_dict).order_by("-level")

    page_object = Pagination(request,queryset)

    page_queryset = page_object.page_queryset

    page_string = page_object.html()

    context = {"queryset":page_queryset, "search_data":search_data, "page_string":page_string}

    return render(request, 'pretty_list.html', context)

class PrettyModelForm(forms.ModelForm):
    # 方式一
    # mobile = forms.CharField(
    #     label="手机号",
    #     validators=[RegexValidator(r'^1[3-9]\d{9}$', '手机号格式错误')],
    # )

    class Meta:
        model = models.PrettyNum
        # fields = ["mobile", "price", "level", "status"]
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

    def clean_mobile(self):
        txt_mobile = self.cleaned_data["mobile"]

        exists = models.PrettyNum.objects.filter(mobile=txt_mobile).exists()
        if exists:
            raise forms.ValidationError("手机号已存在")

        if len(txt_mobile) != 11:
            # 验证不通过
            raise forms.ValidationError("格式错误")
        # 验证通过，用户输入的值返回
        return txt_mobile

def pretty_add(request):
    """ 添加靓号 """
    if request.method == "GET":
        form = PrettyModelForm()
        return render(request, "pretty_add.html", {"form":form})

    # 用户POST提交数据，数据校验
    form = PrettyModelForm(data=request.POST)
    if form.is_valid():
        form.save()
        return redirect("/pretty/list/")

    # 校验失败（在页面上显示错误信息）
    return render(request, "pretty_add.html",{"form":form})


class PrettyEditModelForm(forms.ModelForm):
    # mobile = forms.CharField(disabled=True,label="手机号")
    # mobile = forms.CharField(
    #     label="手机号",
    #     validators=[RegexValidator(r'^1[3-9]\d{9}$', '手机号格式错误')],
    # )

    class Meta:
        model = models.PrettyNum
        fields = ['mobile', 'price', 'level', 'status']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

    def clean_mobile(self):
        # 当前编辑的那一行的ID
        # self.instance.pk
        txt_mobile = self.cleaned_data["mobile"]
        exists = models.PrettyNum.objects.exclude(id=self.instance.pk).filter(mobile=txt_mobile).exists()
        if exists:
            raise forms.ValidationError("手机号已存在")

        if len(txt_mobile) != 11:
            # 验证不通过
            raise forms.ValidationError("格式错误")
        # 验证通过，用户输入的值返回
        return txt_mobile

def pretty_edit(request, nid):
    """ 编辑靓号 """
    row_object = models.PrettyNum.objects.filter(id=nid).first()

    if request.method == "GET":
        form = PrettyEditModelForm(instance=row_object)
        return render(request, "pretty_edit.html", {"form":form})

    form = PrettyEditModelForm(data=request.POST, instance=row_object)

    if form.is_valid():
        form.save()
        return redirect('/pretty/list/')
    return render(request, "pretty_edit.html", {"form":form})

def pretty_delete(request, nid):
    models.PrettyNum.objects.filter(id=nid).delete()
    return redirect('/pretty/list/')

from app01 import models
def admin_list(request):
    """ 管理员列表 """

    # 检查用户是否已登录，已登录，继续向下走，未登录跳转回登录页面。
    # 用户发来请求，获取cookie随机字符串，拿着随机字符串看看session中有没有。
    info = request.session.get("info")
    if not info:
        return redirect('/login/')

    # 搜索
    data_dict = {}
    search_data = request.GET.get("q", "")
    if search_data:
        data_dict["username__contains"] = search_data

    # 根据搜索条件去数据库获取
    queryset = models.Admin.objects.filter(**data_dict)

    # 分页
    page_object = Pagination(request, queryset)

    context = {
        'queryset': page_object.page_queryset,
        'page_string': page_object.html(),
        'search_data': search_data
    }
    return render(request, "admin_list.html", context)

from django import forms
class AdminModelForm(forms.ModelForm):

    confirm_password = forms.CharField(label='确认密码', widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = models.Admin
        fields = ["username", "password"]
        widgets = {
            'password': forms.PasswordInput(render_value=True)
        }

    def clean_password(self):
        pwd = self.cleaned_data.get("password")
        return md5(pwd)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

    def clean_confirm_password(self):
        confirm = md5(self.cleaned_data.get("confirm_password"))
        pwd = self.cleaned_data.get("password")
        if confirm != pwd:
            raise ValidationError("密码不一致")
        return confirm

def admin_add(request):
    """ 添加管理员 """
    title = "新建管理员"
    if request.method == "GET":
        form = AdminModelForm()
        return render(request, "change.html", {'form': form, "title":title})

    form = AdminModelForm(data=request.POST)
    if form.is_valid():
        form.save()
        return redirect('/admin/list/')
    return render(request, "change.html", {'form': form, "title":title})

class AdminEditModelForm(forms.ModelForm):
    class Meta:
        model = models.Admin
        fields = ["username"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}


def admin_edit(request, nid):
    """ 编辑管理员 """
    # 对象
    row_object = models.Admin.objects.filter(id=nid).first()
    if not row_object:
        return redirect("/admin/list/")

    title = "编辑管理员"
    if request.method == "GET":
        form = AdminEditModelForm(instance=row_object)
        return render(request, "change.html", {"form": form, "title": title})

    form = AdminEditModelForm(data=request.POST, instance=row_object)
    if form.is_valid():
        form.save()
        return redirect('/admin/list/')

    return render(request, "change.html",{"form": form, "title": title})

def admin_delete(request, nid):
    """ 删除管理员 """
    models.Admin.objects.filter(id=nid).delete()
    return redirect("/admin/list/")

class AdminResetModelForm(forms.ModelForm):
    confirm_password = forms.CharField(label='确认密码', widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = models.Admin
        fields = ["password", "confirm_password"]
        widgets = {
            "password": forms.PasswordInput(render_value=True)
        }

    def clean_password(self):
        pwd = self.cleaned_data.get("password")
        md5_pwd = md5(pwd)
        # 去数据库校验当前密码和新输入的密码是否一致

        exists = models.Admin.objects.filter(id=self.instance.pk, password=md5_pwd).exists()
        if exists:
            raise ValidationError("密码不能与之前的一致")

        return md5(pwd)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

    def clean_confirm_password(self):
        confirm = md5(self.cleaned_data.get("confirm_password"))
        pwd = self.cleaned_data.get("password")
        if confirm != pwd:
            raise ValidationError("密码不一致")
        return confirm

def admin_reset(request, nid):
    """ 重置密码 """
    row_object = models.Admin.objects.filter(id=nid).first()
    if not row_object:
        return redirect("/admin/list/")

    title = "重置密码 - {}".format(row_object.username)
    if request.method == "GET":
        form = AdminResetModelForm()
        return render(request, "change.html", {"form": form, "title": title})
    form = AdminResetModelForm(data=request.POST, instance=row_object)
    if form.is_valid():
        form.save()
        return redirect("/admin/list/")
    return render(request, "change.html", {"form": form, "title":title})

class LoginForm(forms.Form):
    username = forms.CharField(
        label="用户名",
        widget=forms.TextInput,
        required=True
    )
    password = forms.CharField(
        label="密码",
        widget=forms.PasswordInput,
        required=True
    )
    code = forms.CharField(
        label="验证码",
        widget=forms.TextInput,
        required=True
    )
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 循环找到所有插件，添加了“class”:{"form-control"}
        for name, field in self.fields.items():
            field.widget.attrs = {"class": "form-control", "placeholder": field.label}

    def clean_password(self):
        pwd = self.cleaned_data.get("password")
        return md5(pwd)
def login(request):
    """ 登录页面 """
    if request.method == "GET":
        form = LoginForm()
        return render(request, 'login.html', {'form':form})

    form = LoginForm(request.POST)
    if form.is_valid():
        # 验证码的校验
        user_input_code = form.cleaned_data.pop('code')
        image_code = request.session.get('image_code', "")
        if image_code.upper() != user_input_code.upper():
            form.add_error("code", "验证码错误")
            return render(request, 'login.html', {'form': form})
        # 验证成功，获取的用户名和密码
        # 数据库校验用户名和密码是否正确
        # 去数据库验证是否正确，获取用户对象
        admin_object = models.Admin.objects.filter(**form.cleaned_data).first()
        if not admin_object:
            form.add_error("username", "用户名或密码错误")
            form.add_error("password", "用户名或密码错误")
            return render(request, 'login.html', {'form': form})
        # 用户名和密码正确
        # 网站生成一个随机字符串，写到用户浏览器的cookie中，在写入session中
        request.session["info"] = {'id': admin_object.id, 'name': admin_object.username}
        # session可以保存7天
        request.session.set_expiry(60 * 60 * 24 * 7)

        return redirect("/admin/list/")
    return render(request, 'login.html', {'form': form})

from app01.utils.code import check_code
from io import BytesIO
def image_code(request):
    """ 生成图片验证码 """
    # 调用pillow函数，生成图片
    img, code_string = check_code()

    # 写到自己的session中（以便后续验证码再进行校验）
    request.session['image_code'] = code_string
    # 给Session设置60秒超时
    request.session.set_expiry(60)
    stream = BytesIO()
    img.save(stream, 'png')
    return HttpResponse(stream.getvalue())
def logout(request):
    """ 注销 """
    request.session.clear()

    return redirect("/login/")