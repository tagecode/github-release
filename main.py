import os
import json
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import webbrowser


class GitHubReleaseManager:
    def __init__(self, root):
        self.root = root
        self.root.title("GitHub Release 管理器")
        self.root.geometry("850x700")
        self.root.resizable(False, False)

        # 设置应用图标（如果有）
        try:
            self.root.iconbitmap("github_icon.ico")  # 可选：提供ICO文件路径
        except:
            pass

        # 创建样式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), foreground='#333333')
        self.style.configure('Accent.TButton', foreground='white', background='#238636', font=('Segoe UI', 10, 'bold'))
        self.style.configure('TEntry', font=('Segoe UI', 10))
        self.style.configure('TCombobox', font=('Segoe UI', 10))

        # 创建主框架
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(
            header_frame,
            text="GitHub Release 创建与文件上传工具",
            style='Header.TLabel'
        ).pack(side=tk.LEFT)

        # 添加GitHub图标
        github_btn = ttk.Button(
            header_frame,
            text="GitHub",
            command=lambda: webbrowser.open("https://github.com"),
            width=10
        )
        github_btn.pack(side=tk.RIGHT, padx=5)

        # 创建选项卡
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 配置选项卡
        config_frame = ttk.Frame(notebook, padding=10)
        notebook.add(config_frame, text="配置")

        # 文件选择部分
        file_frame = ttk.LabelFrame(config_frame, text="1. 选择文件", padding=10)
        file_frame.pack(fill=tk.X, pady=10)

        self.file_path = tk.StringVar()
        ttk.Label(file_frame, text="文件路径:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=60)
        file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="浏览...", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)

        # GitHub 信息部分
        github_frame = ttk.LabelFrame(config_frame, text="2. GitHub 信息", padding=10)
        github_frame.pack(fill=tk.X, pady=10)

        # 创建2列布局
        left_col = ttk.Frame(github_frame)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        right_col = ttk.Frame(github_frame)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        # 左侧列
        ttk.Label(left_col, text="GitHub Token:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.github_token = tk.StringVar()
        token_entry = ttk.Entry(left_col, textvariable=self.github_token, width=40, show="*")
        token_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(left_col, text="仓库所有者:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.repo_owner = tk.StringVar()
        ttk.Entry(left_col, textvariable=self.repo_owner).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(left_col, text="仓库名称:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.repo_name = tk.StringVar()
        ttk.Entry(left_col, textvariable=self.repo_name).grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        # 右侧列
        ttk.Label(right_col, text="Release 标签:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.tag_name = tk.StringVar()
        ttk.Entry(right_col, textvariable=self.tag_name).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(right_col, text="Release 名称:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.release_name = tk.StringVar()
        ttk.Entry(right_col, textvariable=self.release_name).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(right_col, text="发布类型:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.release_type = tk.StringVar(value="release")
        ttk.Combobox(right_col, textvariable=self.release_type,
                     values=["release", "prerelease", "draft"], state="readonly").grid(row=2, column=1, padx=5, pady=5,
                                                                                       sticky="ew")

        # Release 描述
        desc_frame = ttk.LabelFrame(config_frame, text="3. Release 描述 (可选)", padding=10)
        desc_frame.pack(fill=tk.X, pady=10)

        self.release_desc = tk.Text(desc_frame, height=6, width=80, font=('Segoe UI', 10))
        self.release_desc.pack(fill=tk.BOTH, expand=True)
        self.release_desc.insert(tk.END, "## 版本说明\n\n- 新增功能\n- 问题修复\n- 性能优化")

        # 操作选项卡
        action_frame = ttk.Frame(notebook, padding=10)
        notebook.add(action_frame, text="操作")

        # 哈希值部分
        hash_frame = ttk.LabelFrame(action_frame, text="文件哈希值", padding=10)
        hash_frame.pack(fill=tk.X, pady=10)

        self.hash_text = scrolledtext.ScrolledText(hash_frame, height=6, width=80, font=('Consolas', 10))
        self.hash_text.pack(fill=tk.BOTH, expand=True)
        self.hash_text.config(state=tk.DISABLED)

        btn_frame = ttk.Frame(hash_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="计算哈希值", command=self.calculate_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制哈希值", command=self.copy_hashes).pack(side=tk.LEFT, padx=5)

        # 日志部分
        log_frame = ttk.LabelFrame(action_frame, text="操作日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=12,
            width=80,
            font=('Consolas', 9),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        # 底部按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=20)

        ttk.Button(
            btn_frame,
            text="创建 Release 并上传文件",
            style="Accent.TButton",
            command=self.create_release_and_upload
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            btn_frame,
            text="清除日志",
            command=self.clear_log
        ).pack(side=tk.RIGHT, padx=10)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(
            root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(5, 2)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 添加示例数据
        self.file_path.set(r"C:\Path\To\Your\File.zip")
        self.github_token.set("ghp_YourGitHubTokenHere")
        self.repo_owner.set("your-username")
        self.repo_name.set("your-repository")
        self.tag_name.set("v1.0.0")
        self.release_name.set("Version 1.0.0 - 稳定版")

        # 绑定事件
        self.tag_name.trace_add("write", self.auto_fill_release_name)

    def auto_fill_release_name(self, *args):
        """当标签名变化时自动填充Release名称"""
        if not self.release_name.get():
            tag = self.tag_name.get()
            if tag:
                self.release_name.set(f"Release {tag}")

    def browse_file(self):
        """打开文件对话框选择文件"""
        file_path = filedialog.askopenfilename(
            title="选择要上传的文件",
            filetypes=[("所有文件", "*.*")]
        )
        if file_path:
            self.file_path.set(file_path)
            self.log(f"已选择文件: {file_path}")

    def calculate_hashes(self):
        """计算并显示文件的哈希值"""
        file_path = self.file_path.get()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("错误", "请选择一个有效的文件")
            return

        self.hash_text.config(state=tk.NORMAL)
        self.hash_text.delete(1.0, tk.END)

        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            modified_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')

            md5_hash = self.calculate_hash(file_path, 'md5')
            sha1_hash = self.calculate_hash(file_path, 'sha1')
            sha256_hash = self.calculate_hash(file_path, 'sha256')

            hash_info = f"文件名: {file_name}\n"
            hash_info += f"文件大小: {file_size:,} 字节\n"
            hash_info += f"修改时间: {modified_time}\n"
            hash_info += f"\nMD5:    {md5_hash}\n"
            hash_info += f"SHA1:   {sha1_hash}\n"
            hash_info += f"SHA256: {sha256_hash}"

            self.hash_text.insert(tk.END, hash_info)
            self.log("文件哈希值计算完成")
        except Exception as e:
            self.hash_text.insert(tk.END, f"错误: {str(e)}")
            self.log(f"计算哈希值时出错: {str(e)}")

        self.hash_text.config(state=tk.DISABLED)

    def calculate_hash(self, file_path, algorithm='sha1'):
        """计算文件的哈希值"""
        hash_func = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }.get(algorithm.lower(), hashlib.sha1)

        with open(file_path, 'rb') as f:
            file_hash = hash_func()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()

    def create_hash_file(self, file_path):
        """为文件创建包含哈希值的文本文件"""
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            modified_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')

            md5_hash = self.calculate_hash(file_path, 'md5')
            sha1_hash = self.calculate_hash(file_path, 'sha1')
            sha256_hash = self.calculate_hash(file_path, 'sha256')

            hash_file_path = f"{file_path}.hashes.txt"
            with open(hash_file_path, 'w', encoding='utf-8') as f:
                f.write(f"文件名: {file_name}\n")
                f.write(f"大小: {file_size:,} 字节\n")
                f.write(f"修改时间: {modified_time}\n")
                f.write(f"\nMD5:    {md5_hash}\n")
                f.write(f"SHA1:   {sha1_hash}\n")
                f.write(f"SHA256: {sha256_hash}\n")

            return hash_file_path
        except Exception as e:
            self.log(f"创建哈希文件失败: {str(e)}")
            return None

    def create_github_release(self):
        """在GitHub上创建新的Release"""
        token = self.github_token.get()
        owner = self.repo_owner.get()
        repo = self.repo_name.get()
        tag = self.tag_name.get()
        name = self.release_name.get()
        body = self.release_desc.get("1.0", tk.END).strip()
        release_type = self.release_type.get()

        url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # 确定发布类型
        prerelease = release_type == "prerelease"
        draft = release_type == "draft"

        payload = {
            "tag_name": tag,
            "name": name,
            "body": body,
            "draft": draft,
            "prerelease": prerelease
        }

        try:
            self.log(f"正在创建Release: {tag}...")
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()

            release_data = response.json()
            release_id = release_data["id"]
            release_url = release_data["html_url"]

            self.log(f"Release 创建成功! ID: {release_id}")
            self.log(f"Release URL: {release_url}")

            return release_id, release_url
        except requests.exceptions.RequestException as e:
            error_msg = self.extract_error_message(e)
            self.log(f"创建Release失败: {error_msg}")
            raise Exception(f"创建Release失败: {error_msg}")

    def upload_to_release(self, release_id, file_path):
        """上传文件到指定的Release"""
        token = self.github_token.get()
        owner = self.repo_owner.get()
        repo = self.repo_name.get()

        upload_url = f"https://uploads.github.com/repos/{owner}/{repo}/releases/{release_id}/assets"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/octet-stream"
        }

        file_name = os.path.basename(file_path)
        params = {"name": file_name}

        try:
            with open(file_path, 'rb') as f:
                response = requests.post(
                    f"{upload_url}?name={file_name}",
                    headers=headers,
                    data=f
                )
                response.raise_for_status()

            asset_data = response.json()
            download_url = asset_data["browser_download_url"]
            size = asset_data["size"]

            self.log(f"✅ 文件上传成功: {file_name}")
            self.log(f"   大小: {size:,} 字节")
            self.log(f"   下载URL: {download_url}")
            return download_url
        except requests.exceptions.RequestException as e:
            error_msg = self.extract_error_message(e)
            self.log(f"❌ 文件上传失败: {error_msg}")
            raise Exception(f"文件上传失败: {error_msg}")

    def extract_error_message(self, exception):
        """从异常中提取错误信息"""
        if hasattr(exception, 'response') and exception.response is not None:
            try:
                error_data = exception.response.json()
                return error_data.get('message', str(exception))
            except json.JSONDecodeError:
                return exception.response.text or str(exception)
        return str(exception)

    def create_release_and_upload(self):
        """创建Release并上传文件"""
        # 验证输入
        file_path = self.file_path.get()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("错误", "请选择一个有效的文件")
            return

        if not self.github_token.get():
            messagebox.showerror("错误", "请输入GitHub Token")
            return

        if not self.repo_owner.get() or not self.repo_name.get():
            messagebox.showerror("错误", "请填写仓库所有者和仓库名称")
            return

        if not self.tag_name.get():
            messagebox.showerror("错误", "请输入Release标签")
            return

        try:
            self.status_var.set("正在创建Release...")
            self.root.update()

            # 创建Release
            release_id, release_url = self.create_github_release()

            # 计算并显示哈希值
            self.calculate_hashes()

            # 上传主文件
            self.status_var.set("正在上传文件...")
            self.root.update()

            self.log(f"开始上传文件: {os.path.basename(file_path)}")
            download_url = self.upload_to_release(release_id, file_path)

            # 创建并上传哈希文件
            self.status_var.set("正在上传哈希文件...")
            self.root.update()

            hash_file = self.create_hash_file(file_path)
            if hash_file:
                self.log(f"开始上传哈希文件: {os.path.basename(hash_file)}")
                self.upload_to_release(release_id, hash_file)
                # 删除本地临时哈希文件
                os.remove(hash_file)

            # 完成
            self.status_var.set("操作成功完成!")
            messagebox.showinfo(
                "成功",
                f"Release 创建并上传文件成功!\n\n"
                f"Release URL: {release_url}\n"
                f"文件下载URL: {download_url}"
            )

            # 在日志中添加成功消息
            self.log("=" * 60)
            self.log("✅ 所有操作成功完成!")
            self.log(f"👉 访问Release页面: {release_url}")

        except Exception as e:
            self.status_var.set(f"错误: {str(e)}")
            messagebox.showerror("错误", f"操作失败: {str(e)}")
            self.log(f"❌ 操作失败: {str(e)}")

    def copy_hashes(self):
        """复制哈希值到剪贴板"""
        if self.hash_text.get("1.0", tk.END).strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.hash_text.get("1.0", tk.END))
            self.log("哈希值已复制到剪贴板")

    def clear_log(self):
        """清除日志"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.log("日志已清除")

    def log(self, message):
        """向日志区域添加消息"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update()


if __name__ == "__main__":
    root = tk.Tk()
    app = GitHubReleaseManager(root)
    root.mainloop()
