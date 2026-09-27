"""漏洞情报监控核心包。

数据流: sources(抓取) -> pipeline(合并/筛选/打分) -> report(渲染) -> notify(分发)。
纯 Python 标准库,零第三方依赖。
"""

__version__ = "2.0.0"
