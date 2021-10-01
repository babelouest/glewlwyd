import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class Buttons extends Component {
  constructor (props) {
    super(props);
    this.state = {
      config: props.config,
      userList: props.userList,
      currentUser: props.currentUser,
      client: props.client,
      newUser: props.newUser,
      newUserScheme: props.newUserScheme,
      canContinue: props.canContinue,
      showGrant: props.showGrant,
      schemeListRequired: props.schemeListRequired,
      bGrantTitle: props.showGrant?i18next.t("login.grant-auth-title"):i18next.t("login.grant-change-title"),
      bGrant: props.showGrant?i18next.t("login.grant-auth"):i18next.t("login.grant-change"),
      showGrantAsterisk: props.showGrantAsterisk,
      selectAccount: props.selectAccount,
      registration: props.registration,
      resetCredentials: props.resetCredentials,
      resetCredentialsShow: props.resetCredentialsShow,
      sessionClosed: props.sessionClosed
    };

    this.clickLogout = this.clickLogout.bind(this);
    this.clickGrant = this.clickGrant.bind(this);
    this.clickContinue = this.clickContinue.bind(this);
    this.newUser = this.newUser.bind(this);
    this.managerUsers = this.managerUsers.bind(this);
    this.changeSessionScheme = this.changeSessionScheme.bind(this);
    this.registerNewUser = this.registerNewUser.bind(this);
    
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      userList: nextProps.userList,
      currentUser: nextProps.currentUser,
      client: nextProps.client,
      config: nextProps.config,
      showGrant: nextProps.showGrant,
      newUser: nextProps.newUser,
      newUserScheme: nextProps.newUserScheme,
      canContinue: nextProps.canContinue,
      schemeListRequired: nextProps.schemeListRequired,
      bGrantTitle: nextProps.showGrant?i18next.t("login.grant-auth-title"):i18next.t("login.grant-change-title"),
      bGrant: nextProps.showGrant?i18next.t("login.grant-auth"):i18next.t("login.grant-change"),
      showGrantAsterisk: nextProps.showGrantAsterisk,
      selectAccount: nextProps.selectAccount,
      registration: nextProps.registration,
      resetCredentials: nextProps.resetCredentials,
      resetCredentialsShow: nextProps.resetCredentialsShow,
      sessionClosed: nextProps.sessionClosed
    });
  }

  clickLogout() {
    apiManager.glewlwydRequest("/auth/?username=" + this.state.currentUser.username, "DELETE")
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'InitProfile'});
      messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      messageDispatcher.sendMessage('App', {type: 'InitProfile'});
      messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
    });
  }
  
  clickGrant() {
    messageDispatcher.sendMessage('App', {type: 'ToggleGrant'});
  }
  
  clickContinue() {
    if (this.state.config.params.callback_url) {
      document.location.href = this.state.config.params.callback_url + (this.state.config.params.callback_url.indexOf("?")>0?"&g_continue":"?g_continue");
    }
  }

  newUser(e, user) {
    e.preventDefault();
    if (!user) {
      messageDispatcher.sendMessage('App', {type: 'NewUser'});
    } else {
      apiManager.glewlwydRequest("/auth/", "POST", {username: user})
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'InitProfile'});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
      });
    }
  }
  
  registerNewUser(e, plugin) {
    e.preventDefault();
    document.location.href = this.state.config.ProfileUrl + "?register=" + encodeURIComponent(plugin) + "&callback_url=" + encodeURIComponent(document.location.href);
  }
  
  resetCredentials(e, plugin) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: 'ResetCredentials'});
  }
  
  managerUsers(e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: 'SelectAccount'});
  }
  
  changeSessionScheme(e, scheme, identify = false) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: 'newUserScheme', scheme: scheme, identify: identify});
  }
  
  cancelResetCredentials() {
    messageDispatcher.sendMessage('App', {type: 'NewUser'});
  }

	render() {
    var bAnother = "", asterisk = "", bContinue = "", bGrant = "", registerTable = [];
    if (this.state.canContinue) {
      bContinue = <button type="button" className="btn btn-success" onClick={this.clickContinue} title={i18next.t("login.continue-title")}>
        <i className="fas fa-play btn-icon"></i>{i18next.t("login.continue")}
      </button>;
    }
    if (this.state.showGrantAsterisk) {
      asterisk = <small><i className="fas fa-asterisk btn-icon-right"></i></small>;
    }
    if (this.state.client) {
      bGrant = 
      <div>
        <a className="dropdown-item" href="#" onClick={this.clickGrant} alt={this.state.bGrantTitle}>
          <i className="fas fa-user-cog btn-icon"></i>{this.state.bGrant}
          {asterisk}
        </a>
        <div className="dropdown-divider"></div>
      </div>;
    }
    if (this.state.currentUser && !this.state.selectAccount) {
      this.state.registration.forEach((register, index) => {
        registerTable.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.registerNewUser(e, register.name)}>{i18next.t(register.message)}</a>);
      });
      var userList = [];
      if (this.state.userList) {
        this.state.userList.forEach((user, index) => {
          if (this.state.currentUser.username === user.username) {
            userList.push(<a className="dropdown-item active" href="#" onClick={(e) => this.newUser(e, user.username)} key={index} alt={user.name || user.username}>{user.name || user.username}</a>);
          } else {
            userList.push(<a className="dropdown-item" href="#" onClick={(e) => this.newUser(e, user.username)} key={index} alt={user.name || user.username}>{user.name || user.username}</a>);
          }
        });
      }
      bAnother = <div className="btn-group" role="group">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="selectNewUser" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i className="fas fa-users btn-icon"></i>{i18next.t("login.login-another")}
        </button>
        <div className="dropdown-menu" aria-labelledby="selectNewUser">
          <a className="dropdown-item" href="#" onClick={(e) => this.newUser(e, false)}>{i18next.t("profile.menu-session-new")}</a>
          <a className="dropdown-item" href="#" onClick={(e) => this.managerUsers(e)}>{i18next.t("login.manage-users")}</a>
          {registerTable}
          <div className="dropdown-divider"></div>
          {userList}
        </div>
      </div>;
  		return (
        <div className="text-center">
          <div className="btn-group" role="group">
            {bContinue}
            <button type="button" className="btn btn-danger" onClick={this.clickLogout}>
              <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
            </button>
          </div>
          <div>
            <hr/>
            <div className="btn-group" role="group">
              <div className="btn-group" role="group">
                <button className="btn btn-secondary dropdown-toggle" type="button" id="selectGrant" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  <i className="fas fa-user-cog btn-icon"></i>{i18next.t("login.login-handle")}{asterisk}
                </button>
                <div className="dropdown-menu" aria-labelledby="selectGrant">
                  {bGrant}
                  <a className="dropdown-item" href={this.state.config.ProfileUrl||""} target="_blank" rel="noopener noreferrer">{i18next.t("login.update-profile")}</a>
                </div>
              </div>
              {bAnother}
            </div>
          </div>
        </div>
  		);
    } else if (this.state.newUser) {
      if (this.state.resetCredentials) {
        this.state.resetCredentials.forEach((resetCred, index) => {
          registerTable.push(
            <button key={index+this.state.config.register.length} type="button" className="btn btn-danger" onClick={(e) => this.resetCredentials(e, resetCred.name)}>
              {i18next.t(resetCred.message)}
            </button>
          );
        });
      }
      if (this.state.registration && this.state.config.register) {
        this.state.config.register.forEach((register, index) => {
          registerTable.push(
            <button key={index} type="button" className="btn btn-success" onClick={(e) => this.registerNewUser(e, register.name)}>
              {i18next.t(register.message)}
            </button>
          );
        });
      }
      var btnTitleJsx = i18next.t("login.login-choose-scheme");
      var schemeList = [];
      if (this.state.config.sessionSchemes && this.state.config.sessionSchemes.length && !this.state.sessionClosed) {
        if (!this.state.newUserScheme) {
          schemeList.push(
            <a key={0} className="dropdown-item active" href="#" onClick={(e) => this.changeSessionScheme(e, false)} alt={i18next.t("login.password-title")}>
              {i18next.t("login.password-title")}
            </a>
          );
        } else {
          schemeList.push(
            <a key={0} className="dropdown-item" href="#" onClick={(e) => this.changeSessionScheme(e, false)} alt={i18next.t("login.password-title")}>
              {i18next.t("login.password-title")}
            </a>
          );
        }
        schemeList.push(<div key={1} className="dropdown-divider"></div>);
        this.state.config.sessionSchemes.forEach((scheme, index) => {
          if (scheme.show_nopassword_form !== false) {
            if (scheme.scheme_name === this.state.newUserScheme) {
              if (this.state.newUserScheme) {
                btnTitleJsx = i18next.t(scheme.scheme_display_name);
              }
              schemeList.push(
                <a key={(index+2)} className="dropdown-item active" href="#" onClick={(e) => this.changeSessionScheme(e, scheme.scheme_name, !!scheme.identify)} alt={i18next.t(scheme.scheme_display_name)}>
                  {i18next.t(scheme.scheme_display_name)}
                </a>
              );
            } else {
              schemeList.push(
                <a key={(index+2)} className="dropdown-item" href="#" onClick={(e) => this.changeSessionScheme(e, scheme.scheme_name, !!scheme.identify)} alt={i18next.t(scheme.scheme_display_name)}>
                  {i18next.t(scheme.scheme_display_name)}
                </a>
              );
            }
          }
        });
        return (
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-primary dropdown-toggle" type="button" id="selectScheme" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-user-lock btn-icon"></i>{btnTitleJsx}
              </button>
              <div className="dropdown-menu" aria-labelledby="selectScheme">
                {schemeList}
              </div>
            </div>
            {registerTable}
          </div>
        );
      } else {
        return (
        <div>
          {registerTable}
        </div>
        );
      }
    } else if (this.state.resetCredentialsShow) {
      return (
        <button type="button" className="btn btn-secondary" onClick={this.cancelResetCredentials}>
          {i18next.t("login.btn-cancel")}
        </button>
      );
    } else {
      return ("");
    }
	}
}

export default Buttons;
