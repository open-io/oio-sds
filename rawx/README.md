# Upgrading dependencies

From time to time, it could be interesting to upgrade go dependencies.

```
# upgrade dependencies
go get -u
# adds any missing module requirements + removes unnecessary entries 
go mod tidy
```
