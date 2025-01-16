#pragma once

#include "Handle.h"

#include <utility>

class FindFile {
public:
	FindFile() = default;

	explicit FindFile(LPCWSTR fileName) noexcept
		: Handle(FindFirstFileW(fileName, &this->Data))
	{ }

	explicit operator bool() const noexcept {
		return static_cast<bool>(this->Handle);
	}

	FindFile& operator ++ () noexcept {
		if(this->Handle) {
			if(FindNextFileW(this->Handle, &this->Data) == FALSE) {
				this->Handle.clear();
			}
		}
		return *this;
	}

	WIN32_FIND_DATAW const* operator -> () const noexcept {
		return &this->Data;
	}

	WIN32_FIND_DATAW const& operator * () const noexcept {
		return this->Data;
	}

private:
	FindHandle Handle;
	WIN32_FIND_DATAW Data;
};
