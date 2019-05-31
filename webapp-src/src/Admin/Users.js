import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Users extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      users: props.users
    }

    messageDispatcher.subscribe('Users', (message) => {
    });

    this.addUser = this.addUser.bind(this);
    this.editUser = this.editUser.bind(this);
    this.deleteUser = this.deleteUser.bind(this);
    this.handleChangeSearchPattern = this.handleChangeSearchPattern.bind(this);
    this.searchUsers = this.searchUsers.bind(this);
    this.navigate = this.navigate.bind(this);
    this.navigatePerPage = this.navigatePerPage.bind(this);
    this.delegateUser = this.delegateUser.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      users: nextProps.users
    });
  }

  addUser(e) {
    messageDispatcher.sendMessage('App', {type: "add", role: "user"});
  }

  editUser(e, user) {
    messageDispatcher.sendMessage('App', {type: "edit", role: "user", user: user});
  }

  deleteUser(e, user) {
    messageDispatcher.sendMessage('App', {type: "delete", role: "user", user: user});
  }

  handleChangeSearchPattern (e) {
    var users = this.state.users;
    users.searchPattern = e.target.value;
    this.setState({users: users});
  }

  searchUsers (e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "user", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset, limit: this.state.users.limit});
  }

  navigate(e, direction) {
    if (direction > 0) {
      messageDispatcher.sendMessage('App', {type: "search", role: "user", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset+this.state.users.limit, limit: this.state.users.limit});
    } else if (this.state.users.offset) {
      messageDispatcher.sendMessage('App', {type: "search", role: "user", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset-this.state.users.limit, limit: this.state.users.limit});
    }
  }

  navigatePerPage(e, limit) {
    messageDispatcher.sendMessage('App', {type: "search", role: "user", pattern: this.state.users.searchPattern, offset: this.state.users.offset, limit: limit});
  }
  
  delegateUser(e, user) {
    window.open(this.state.config.ProfileUrl + "?delegate=" + user.username, '_blank');
  }
  
	render() {
    var users = [];
    this.state.users.list.forEach((user, index) => {
      users.push(<tr key={index}>
        <td>{user.source}</td>
        <td>{user.username}</td>
        <td>{user.name||""}</td>
        <td>{user.email||""}</td>
        <td>{(user.enabled?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.delegateUser(e, user)} title={i18next.t("admin.delegate")}>
              <i className="fas fa-id-card"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editUser(e, user)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteUser(e, user)} title={i18next.t("admin.delete")}>
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </td>
      </tr>);
    });
		return (
    <table className="table table-responsive table-striped">
      <thead>
        <tr>
          <th colSpan="2">
            <h4>{i18next.t("admin.user-list-title")}</h4>
          </th>
          <th colSpan="4">
            <form className="form-inline" onSubmit={(e) => this.searchUsers(e)}>
              <div className="input-group mr-sm-2">
                <input className="form-control" type="search" placeholder={i18next.t("admin.nav-search-placeholder")} aria-label="Search" onChange={this.handleChangeSearchPattern} value={this.state.users.searchPattern||""}/>
                <button className="btn btn-secondary my-sm-0" type="submit" title={i18next.t("admin.nav-search-title")} onClick={(e) => this.searchUsers(e)}>{i18next.t("admin.nav-search")}</button>
              </div>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, -1)} title={i18next.t("admin.nav-previous")} disabled={!this.state.users.offset}>
                  <i className="fas fa-backward"></i>
                </button>
                <div className="btn-group" role="group">
                  <button id="btnGroupNavPerPage" type="button" className="btn btn-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    {i18next.t("admin.nav-per-page")}
                  </button>
                  <div className="dropdown-menu" aria-labelledby="btnGroupNavperPage">
                    <a className={"dropdown-item" + (this.state.users.limit===10?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 10)}>10</a>
                    <a className={"dropdown-item" + (this.state.users.limit===20?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 20)}>20</a>
                    <a className={"dropdown-item" + (this.state.users.limit===50?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 50)}>50</a>
                    <a className={"dropdown-item" + (this.state.users.limit===100?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 100)}>100</a>
                  </div>
                </div>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, 1)} title={i18next.t("admin.nav-next")}>
                  <i className="fas fa-forward"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.addUser(e)} title={i18next.t("admin.user-add")}>
                  <i className="fas fa-plus"></i>
                </button>
              </div>
            </form>
          </th>
        </tr>
        <tr>
          <th>
            {i18next.t("admin.source")}
          </th>
          <th>
            {i18next.t("admin.username")}
          </th>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th>
            {i18next.t("admin.email")}
          </th>
          <th>
            {i18next.t("admin.enabled")}
          </th>
          <th>
          </th>
        </tr>
      </thead>
      <tbody>
        {users}
        <tr>
          <td colSpan="6">
            {i18next.t("admin.nav-footer", {offset: this.state.users.offset, limit: this.state.users.limit})}
          </td>
        </tr>
      </tbody>
    </table>
		);
	}
}

export default Users;
