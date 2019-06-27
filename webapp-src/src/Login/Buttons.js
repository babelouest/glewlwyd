import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class Buttons extends Component {
  constructor (props) {
    super(props);
    this.state = {
      config: props.config,
      userList: props.userList,
      currentUser: props.currentUser,
      newUser: props.newUser,
      newUserScheme: props.newUserScheme,
      canContinue: props.canContinue,
      showGrant: props.showGrant,
      schemeListRequired: props.schemeListRequired,
      bGrantTitle: props.showGrant?i18next.t("login.grant-auth-title"):i18next.t("login.grant-change-title"),
      bGrant: props.showGrant?i18next.t("login.grant-auth"):i18next.t("login.grant-change"),
      showGrantAsterisk: props.showGrantAsterisk
    };

    this.clickLogout = this.clickLogout.bind(this);
    this.clickGrant = this.clickGrant.bind(this);
    this.clickContinue = this.clickContinue.bind(this);
    this.newUser = this.newUser.bind(this);
    this.changeSessionScheme = this.changeSessionScheme.bind(this);
    
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      userList: nextProps.userList,
      currentUser: nextProps.currentUser,
      config: nextProps.config,
      showGrant: nextProps.showGrant,
      newUser: nextProps.newUser,
      newUserScheme: nextProps.newUserScheme,
      canContinue: nextProps.canContinue,
      schemeListRequired: nextProps.schemeListRequired,
      bGrantTitle: nextProps.showGrant?i18next.t("login.grant-auth-title"):i18next.t("login.grant-change-title"),
      bGrant: nextProps.showGrant?i18next.t("login.grant-auth"):i18next.t("login.grant-change"),
      showGrantAsterisk: nextProps.showGrantAsterisk
    });
  }

  clickLogout() {
    apiManager.glewlwydRequest("/auth/", "DELETE")
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'InitProfile'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
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
  
  changeSessionScheme(e, scheme) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: 'newUserScheme', scheme: scheme});
  }

	render() {
    var bAnother = "", asterisk = "";
    var bContinue = <button type="button" className="btn btn-primary" onClick={this.clickContinue} title={i18next.t("login.continue-title")} disabled={!this.state.canContinue}>
      <i className="fas fa-play btn-icon"></i>{i18next.t("login.continue")}
    </button>;
    var bGrant = <button type="button" className="btn btn-primary" onClick={this.clickGrant} title={this.state.bGrantTitle||""}>
      <i className="fas fa-user-cog btn-icon"></i>{this.state.bGrant}
    </button>;
    if (this.state.showGrantAsterisk) {
      asterisk = <small><i className="fas fa-asterisk btn-icon-right"></i></small>;
    }
    if (this.state.currentUser) {
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
        <button className="btn btn-primary dropdown-toggle" type="button" id="selectNewUser" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i className="fas fa-users btn-icon"></i>{i18next.t("login.login-another")}
        </button>
        <div className="dropdown-menu" aria-labelledby="selectNewUser">
          <a className="dropdown-item" href="#" onClick={(e) => this.newUser(e, false)}>{i18next.t("login.login-another-new")}</a>
          <div className="dropdown-divider"></div>
          {userList}
        </div>
      </div>;
  		return (
        <div>
          <div className="btn-group" role="group">
            {bContinue}
            <button type="button" className="btn btn-primary" onClick={this.clickLogout}>
              <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
            </button>
          </div>
          <hr/>
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-primary dropdown-toggle" type="button" id="selectGrant" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-user-cog btn-icon"></i>{i18next.t("login.login-handle")}{asterisk}
              </button>
              <div className="dropdown-menu" aria-labelledby="selectGrant">
                <a className="dropdown-item" href="#" onClick={this.clickGrant} alt={this.state.bGrantTitle}>
                  {this.state.bGrant}
                  {asterisk}
                </a>
                <div className="dropdown-divider"></div>
                <a className="dropdown-item" href={this.state.config.ProfileUrl||""} target="_blank">{i18next.t("login.update-profile")}</a>
              </div>
            </div>
            {bAnother}
          </div>
        </div>
  		);
    } else if (this.state.newUser) {
      var schemeList = [];
      if (this.state.config.sessionSchemes && this.state.config.sessionSchemes.length) {
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
              schemeList.push(
                <a key={(index+2)} className="dropdown-item active" href="#" onClick={(e) => this.changeSessionScheme(e, scheme.scheme_name)} alt={i18next.t(scheme.scheme_display_name)}>
                  {i18next.t(scheme.scheme_display_name)}
                </a>
              );
            } else {
              schemeList.push(
                <a key={(index+2)} className="dropdown-item" href="#" onClick={(e) => this.changeSessionScheme(e, scheme.scheme_name)} alt={i18next.t(scheme.scheme_display_name)}>
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
                <i className="fas fa-user-lock btn-icon"></i>{i18next.t("login.login-choose-scheme")}
              </button>
              <div className="dropdown-menu" aria-labelledby="selectScheme">
                {schemeList}
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={(e) => this.newUser(e, false)}>
              <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
            </button>
          </div>
        );
      } else {
        return ("");
      }
    } else {
      return ("");
    }
	}
}

export default Buttons;
