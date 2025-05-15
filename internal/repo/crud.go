package repo

import (
	"fmt"
	"log"
	"svm/internal/entity/dataSetFields"
	"svm/internal/entity/userModel"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (d *Database) AddNewUser(username, email, password string) error {
	hashedPassword, errOfHashed := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if errOfHashed != nil {
		log.Println("Ошибка при хэшировании:", errOfHashed)
		return errOfHashed
	}

	_, err := d.db.Exec("insert into svm_network.users(name, email, password_hash, created_at, updated_at, is_active) values(?,?,?,?,?,?)", username, email, hashedPassword, time.Now(), time.Now(), true)

	if err != nil {
		return err
	}

	return nil
}

func (d *Database) CheckPassword(email, password string) bool {
	fmt.Println(password)
	var password_hash string
	err := d.db.QueryRow("select password_hash from svm_network.users where email = ?", email).Scan(&password_hash)

	if err != nil {
		log.Println("Ошибка: ", err)
	}

	errOfCheckHash := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))

	if errOfCheckHash != nil {
		log.Println("Пароли не совпадают: ", errOfCheckHash)
		return false
	} else {
		log.Println("Пароли совпадают")
		return true
	}
}

func (d *Database) CheckPasswordById(userId int, password string) bool {
	var password_hash string
	err := d.db.QueryRow("select password_hash from svm_network.users where id = ?", userId).Scan(&password_hash)

	if err != nil {
		log.Println("Ошибка: ", err)
	}

	errOfCheckHash := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))

	if errOfCheckHash != nil {
		log.Println("Пароли не совпадают: ", errOfCheckHash)
		return false
	} else {
		log.Println("Пароли совпадают")
		return true
	}
}

func (d *Database) GetUserId(email string) int {
	var userId int
	err := d.db.QueryRow("select id from svm_network.users where email = ?", email).Scan(&userId)

	if err != nil {
		return 0
	} else {
		return userId
	}
}

func (d *Database) CheckExist(email string) bool {
	var userId int
	err := d.db.QueryRow("select id from svm_network.users where email = ?", email).Scan(&userId)

	if err != nil {
		return false
	} else {
		return true
	}
}

func (d *Database) DeleteUserById(userId int) error {
	_, errOfDel := d.db.Exec("delete from svm_network.users where id = ?", userId)

	if errOfDel != nil {
		log.Println(errOfDel)
		return errOfDel
	}

	return nil
}

func (d *Database) AddPersonalInfo(first_name, last_name, email string, userId int) error {
	_, errProfiles := d.db.Exec("insert into svm_network.user_profiles(user_id, first_name, last_name) values(?,?,?)", userId, first_name, last_name)

	if errProfiles != nil {
		log.Println(errProfiles)
		return errProfiles
	}

	return nil
}

func (d *Database) CheckExistPersonalInfo(userId int) bool {
	var userID string
	err := d.db.QueryRow("select user_id from svm_network.user_profiles where user_id = ?", userId).Scan(&userID)

	if err != nil {
		log.Println("Персональных данных для такого пользователя нет")
		return false
	} else {
		log.Println("Персональные данные найдены")
		return true
	}
}

func (d *Database) UpdatePersonalInfo(first_name, last_name, email string, userId int) error {
	_, errOfUpdating := d.db.Exec("update svm_network.user_profiles set first_name = ?, last_name = ? where user_id = ?", first_name, last_name, userId)

	if errOfUpdating != nil {
		log.Println(errOfUpdating)
		return errOfUpdating
	}

	_, errOfUpdatingEmail := d.db.Exec("update svm_network.users set email = ? where id = ?", email, userId)

	if errOfUpdatingEmail != nil {
		log.Println(errOfUpdatingEmail)
		return errOfUpdatingEmail
	}

	return nil
}

func (d *Database) UpdateUserPassword(newPassword []byte, userId int) error {
	_, errOfUpdating := d.db.Exec("update svm_network.users set password_hash = ? where id = ?", string(newPassword), userId)

	if errOfUpdating != nil {
		log.Println(errOfUpdating)
		return errOfUpdating
	}

	return nil
}

func (d *Database) LoadPersonalInfo(userId int) userModel.UserProfile {
	var userProfile userModel.UserProfile
	userProfile.User_Id = userId

	errOfLoading := d.db.QueryRow("select first_name, last_name from svm_network.user_profiles where user_id = ?", userId).Scan(&userProfile.First_Name, &userProfile.Last_Name)

	if errOfLoading != nil {
		log.Println(errOfLoading)
	}

	errOfLoadingSecret := d.db.QueryRow("select email from svm_network.users where id = ?", userId).Scan(&userProfile.Email)

	if errOfLoadingSecret != nil {
		log.Println(errOfLoadingSecret)
	}

	return userProfile
}

func (d *Database) LoadReports(userId int) []dataSetFields.Record {
	// Выборка данных
	rows, err := d.db.Query("SELECT id, timestamp, is_anomaly, duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, user_id, created_at FROM network_analysis_reports where user_id = ?", userId)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Массив для хранения записей
	var records []dataSetFields.Record

	// Обработка строк
	for rows.Next() {
		var r dataSetFields.Record
		err := rows.Scan(
			&r.ID, &r.TimestampStr, &r.IsAnomaly, &r.Duration, &r.ProtocolType, &r.Service, &r.Flag,
			&r.SrcBytes, &r.DstBytes, &r.Land, &r.WrongFragment, &r.Urgent, &r.Hot, &r.NumFailedLogins,
			&r.LoggedIn, &r.NumCompromised, &r.RootShell, &r.SuAttempted, &r.NumRoot, &r.NumFileCreations,
			&r.NumShells, &r.NumAccessFiles, &r.NumOutboundCmds, &r.IsHostLogin, &r.IsGuestLogin,
			&r.Count, &r.SrvCount, &r.SerrorRate, &r.SrvSerrorRate, &r.RerrorRate, &r.SrvRerrorRate,
			&r.SameSrvRate, &r.DiffSrvRate, &r.SrvDiffHostRate, &r.DstHostCount, &r.DstHostSrvCount,
			&r.DstHostSameSrvRate, &r.DstHostDiffSrvRate, &r.DstHostSameSrcPortRate, &r.DstHostSrvDiffHostRate,
			&r.DstHostSerrorRate, &r.DstHostSrvSerrorRate, &r.DstHostRerrorRate, &r.DstHostSrvRerrorRate,
			&r.UserID, &r.CreatedAtStr,
		)
		if err != nil {
			log.Fatal(err)
		}
		r.Timestamp, err = time.Parse("2006-01-02 15:04:05", r.TimestampStr)
		if err != nil {
			log.Fatal("Ошибка парсинга даты:", err)
		}

		r.CreatedAt, err = time.Parse("2006-01-02 15:04:05", r.CreatedAtStr)
		if err != nil {
			log.Fatal("Ошибка парсинга даты:", err)
		}

		records = append(records, r)
	}

	// Проверка ошибок после итерации
	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return records
}

// ReportExistsForUser проверяет, существует ли отчёт у пользователя
func (d *Database) ReportExistsForUser(reportID, userID int) (bool, error) {
	var exists bool
	err := d.db.QueryRow("SELECT EXISTS(SELECT 1 FROM network_analysis_reports WHERE id = ? AND user_id = ?)", reportID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки существования отчёта: %w", err)
	}
	return exists, nil
}

// DeleteReport удаляет отчёт по ID
func (d *Database) DeleteReportById(reportID int) error {
	result, err := d.db.Exec("DELETE FROM network_analysis_reports WHERE id = ?", reportID)
	if err != nil {
		return fmt.Errorf("ошибка удаления отчёта: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("ошибка получения количества удалённых строк: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("отчёт не найден")
	}

	log.Printf("Удалено отчётов: %d", rowsAffected)
	return nil
}
